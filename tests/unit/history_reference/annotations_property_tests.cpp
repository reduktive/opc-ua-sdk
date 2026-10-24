// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the Annotations Property helper (history_reference lib).
// Covers SVR-HIST-ANN-001 (the Annotations Property is modelled on a HistoricalDataNode that supports
// Annotations) and SVR-HIST-ANN-009 (the property is added ONLY when the delegate supports
// Annotations). The property is built through the generated ua::Property PropertyType helper, so the
// tests run against a real NS0-loaded address space (TestServer) rather than the bare engine/store.

#include "ua_history_annotations_property.h"
#include "ua_history_engine_delegate.h"
#include "history_test_support.h"
#include "ua_history_sqlite_store.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_annotation.h"
#include "ua_base_data_variable.h"
#include "ua_datatype_id.h"
#include "ua_instantiation_options.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_test_server.h"
#include "ua_value_rank.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <atomic>
#include <memory>

namespace
{

using ua::AccessLevelType;
using ua::AddressSpace;
using ua::BaseDataVariable;
using ua::DataTypeId;
using ua::InstantiationOptions;
using ua::NodeId;
using ua::QualifiedName;
using ua::ReferenceTypeId;
using ua::Status;
using ua::ValueRank;
using ua::VariableInstantiationAttributes;

// Instantiation options whose first allocated node takes `rootId` and subsequent nodes get unique ids
// - the same root-pinning pattern the seeds use.
InstantiationOptions options_with_root(const ua::server::Server& server, const NodeId& rootId)
{
  InstantiationOptions options{.parentReferenceType = NodeId{ReferenceTypeId::Organizes},
    .nodeIdAllocator = {},
    .optionalChildFilter = {},
    .targetNamespaceIndex = std::nullopt};
  options.nodeIdAllocator = [rootId, first = true](uint16_t ns, const QualifiedName&) mutable -> NodeId
  {
    if (first)
    {
      first = false;
      return rootId;
    }
    static std::atomic<uint32_t> counter{77000};
    return NodeId{ns, counter.fetch_add(1)};
  };
  return options;
}

// Create a historised Double DataVariable under the Objects folder and return its NodeId.
NodeId make_historised_node(AddressSpace addressSpace, const ua::server::Server& server, const NodeId& nodeId,
  std::string_view browseName)
{
  const VariableInstantiationAttributes attrs{.dataType = NodeId{DataTypeId::Double},
    .valueRank = ValueRank::scalar,
    .accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::HistoryRead,
      AccessLevelType::Bit::HistoryWrite}};
  auto variable = BaseDataVariable::try_create_sync(addressSpace,
    NodeId{ua::ObjectId::ObjectsFolder},
    QualifiedName{nodeId.namespace_index(), std::string{browseName}},
    options_with_root(server, nodeId),
    attrs)
                    .value();
  variable.release();
  return variable.node_id();
}

// A history delegate that advertises NO capabilities (in particular no annotation support).
class NoAnnotationDelegate : public ua::NamespaceHistoryDelegate
{
public:
  Capabilities capabilities() const noexcept override
  {
    return Capabilities{};
  }
};

// Whether `parent` has a forward HasProperty reference to a local node named "Annotations".
bool has_annotations_property(AddressSpace addressSpace, const NodeId& parent)
{
  auto parentNode = addressSpace.find_node_sync(parent);
  for (const auto& ref : parentNode.get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
      continue;
    if (ref.type_id() != NodeId{ReferenceTypeId::HasProperty})
      continue;
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    auto child = addressSpace.try_find_node_sync(target.node_id());
    if (child.is_good() && child.value().get_browse_name().name() == "Annotations")
      return true;
  }
  return false;
}

}  // namespace

// @relation(AC-SVR-HIST-ANN-001-A-HISTORISED-NODE-WHOSE-HISTORIAN-SUPPORTS, scope=function)

// SVR-HIST-ANN-001/009: a delegate that supports Annotations -> the Annotations Property is added with
// the spec-mandated shape (BrowseName "Annotations" in ns=0, DataType Annotation, scalar, reached via
// HasProperty) and its Value reads back as a well-formed Annotation marker.
// @relation(SVR-HIST-ANN-009, scope=function)
TEST(AnnotationsProperty, AddedWhenDelegateSupportsAnnotations)
{
  ua::test_helpers::TestServer server;
  server.create();
  auto addressSpace = server.server().address_space();

  const NodeId nodeId{1, "Historised.Supported"};
  make_historised_node(addressSpace, server.server(), nodeId, "HistorisedSupported");

  // SqliteHistoryStore(":memory:") backs a HistoryEngineDelegate that advertises read + insert annotations.
  auto store = std::make_unique<ua::history::SqliteHistoryStore>(":memory:", ua::history::test::make_codec());
  ua::history::HistoryEngineDelegate delegate{std::move(store)};
  ASSERT_TRUE(delegate.capabilities().readAnnotations || delegate.capabilities().insertAnnotation);

  auto result = ua::history::add_annotations_property(
    addressSpace, nodeId, delegate, options_with_root(server.server(), NodeId{1, "Historised.Annotations"}));
  ASSERT_TRUE(result.is_good()) << "status=" << result.status_code().as_uint32();

  const auto propertyId = result.value().node_id();
  auto propertyNode = addressSpace.find_node_sync(propertyId);
  EXPECT_EQ(propertyNode.get_browse_name().name(), "Annotations");
  EXPECT_EQ(propertyNode.get_browse_name().namespace_index(), 0);

  auto variable = propertyNode.as<ua::VariableAccessor>();
  ASSERT_TRUE(variable);
  EXPECT_EQ(variable->get_data_type(), NodeId{DataTypeId::Annotation});
  EXPECT_TRUE(variable->get_value_rank().is_scalar());

  EXPECT_TRUE(has_annotations_property(addressSpace, nodeId))
    << "Annotations Property must be reachable from the node via HasProperty";

  // The marker Value reads back as an Annotation (presence is the contract; data flows via HistoryRead).
  auto value = variable->try_read_value_sync();
  ASSERT_TRUE(value.is_good());
  EXPECT_NE(value.value().value().try_as<ua::Annotation>(), nullptr);
}

// @relation(AC-SVR-HIST-ANN-001-A-HISTORISED-NODE-WHOSE-HISTORIAN-SUPPORTS, scope=function)

// SVR-HIST-ANN-009: a delegate that does NOT support Annotations -> the helper refuses to add the
// property (Bad_NotSupported) and no "Annotations" child is created.
// @relation(SVR-HIST-ANN-009, scope=function)
TEST(AnnotationsProperty, NotAddedWhenDelegateLacksAnnotations)
{
  ua::test_helpers::TestServer server;
  server.create();
  auto addressSpace = server.server().address_space();

  const NodeId nodeId{1, "Historised.Unsupported"};
  make_historised_node(addressSpace, server.server(), nodeId, "HistorisedUnsupported");

  NoAnnotationDelegate delegate;
  auto result = ua::history::add_annotations_property(
    addressSpace, nodeId, delegate, options_with_root(server.server(), NodeId{1, "Unsupported.Annotations"}));

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadNotSupported});
  EXPECT_NE(result.error_detail(), nullptr) << "the refusal must carry an ErrorDetail";
  EXPECT_FALSE(has_annotations_property(addressSpace, nodeId))
    << "no Annotations Property may be created when the delegate lacks annotation support";
}
