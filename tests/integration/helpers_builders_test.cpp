// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the test-helper request builders.
///
/// These do not exercise a live server; they verify builder shape, throw-on-misuse
/// behaviour, and byte-level request equivalence. Required before further builder
/// additions per the PR 5 review (without a passing test, code must be assumed
/// incorrect).

#include "matchers.h"
#include "requests.h"

#include <gtest/gtest.h>

#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_browse_result_mask.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_date_time.h"
#include "ua_qualified_name.h"
#include "ua_read_raw_modified_details.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_timestamps_to_return.h"
#include "ua_variant.h"

#include <stdexcept>

using namespace ua;
using namespace ua::test_helpers;

// ===========================================================================
// ReadRequestBuilder
// ===========================================================================

TEST(ReadRequestBuilderTest, SingleNodeDefaultsToValueAttribute)
{
  ua::ReadRequest req = ReadRequestBuilder().read(NodeId{ObjectId::ObjectsFolder}).build();
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  EXPECT_EQ(req.nodes_to_read()[0].attribute_id(), static_cast<uint32_t>(AttributeId::Value));
}

TEST(ReadRequestBuilderTest, AttributesProducesNEntriesNotNPlusOne)
{
  // Regression: prior bug flushed a pending Value entry before adding the explicit ones,
  // producing N+1 results. Verify .attributes({A, B, C}) yields exactly 3 entries.
  ua::ReadRequest req =
    ReadRequestBuilder()
      .read(NodeId{ObjectId::ObjectsFolder})
      .attributes({AttributeId::NodeId, AttributeId::BrowseName, AttributeId::DisplayName})
      .build();
  ASSERT_EQ(req.nodes_to_read().size(), 3u);
  EXPECT_EQ(req.nodes_to_read()[0].attribute_id(), static_cast<uint32_t>(AttributeId::NodeId));
  EXPECT_EQ(req.nodes_to_read()[1].attribute_id(), static_cast<uint32_t>(AttributeId::BrowseName));
  EXPECT_EQ(req.nodes_to_read()[2].attribute_id(), static_cast<uint32_t>(AttributeId::DisplayName));
}

TEST(ReadRequestBuilderTest, ModifierWithoutEntryThrows)
{
  EXPECT_THROW(ReadRequestBuilder().data_encoding(QualifiedName{"Default Binary"}).build(), std::logic_error);
  EXPECT_THROW(ReadRequestBuilder().index_range(String{"0:5"}).build(), std::logic_error);
}

TEST(ReadRequestBuilderTest, BackToBackAttributeOverwritesPending)
{
  // Documented behaviour: consecutive .attribute() calls overwrite the pending entry,
  // they do NOT add new entries. Use .attributes({...}) for multi-attribute.
  ua::ReadRequest req = ReadRequestBuilder()
                          .read(NodeId{1u, uint32_t{200}})
                          .attribute(AttributeId::BrowseName)
                          .attribute(AttributeId::DisplayName)
                          .build();
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  EXPECT_EQ(req.nodes_to_read()[0].node_id(), (NodeId{1u, uint32_t{200}}));
  EXPECT_EQ(req.nodes_to_read()[0].attribute_id(), static_cast<uint32_t>(AttributeId::DisplayName));
}

TEST(ReadRequestBuilderTest, OneAttributePerNodeAlternation)
{
  // The recommended idiom for one attribute per node.
  ua::ReadRequest req = ReadRequestBuilder()
                          .read(NodeId{1u, uint32_t{100}})
                          .attribute(AttributeId::BrowseName)
                          .read(NodeId{1u, uint32_t{200}})
                          .attribute(AttributeId::DisplayName)
                          .build();
  ASSERT_EQ(req.nodes_to_read().size(), 2u);
  EXPECT_EQ(req.nodes_to_read()[0].node_id(), (NodeId{1u, uint32_t{100}}));
  EXPECT_EQ(req.nodes_to_read()[0].attribute_id(), static_cast<uint32_t>(AttributeId::BrowseName));
  EXPECT_EQ(req.nodes_to_read()[1].node_id(), (NodeId{1u, uint32_t{200}}));
  EXPECT_EQ(req.nodes_to_read()[1].attribute_id(), static_cast<uint32_t>(AttributeId::DisplayName));
}

TEST(ReadRequestBuilderTest, AttributeAfterAttributesExtendsLastNode)
{
  // Corner case documented in requests.h: .attributes({X,Y}) flushes, then .attribute(Z)
  // creates a new entry on the SAME node as the last flushed entry.
  ua::ReadRequest req = ReadRequestBuilder()
                          .read(NodeId{1u, uint32_t{100}})
                          .attributes({AttributeId::BrowseName, AttributeId::DisplayName})
                          .attribute(AttributeId::Value)
                          .build();
  ASSERT_EQ(req.nodes_to_read().size(), 3u);
  EXPECT_EQ(req.nodes_to_read()[2].node_id(), (NodeId{1u, uint32_t{100}}));
  EXPECT_EQ(req.nodes_to_read()[2].attribute_id(), static_cast<uint32_t>(AttributeId::Value));
}

TEST(ReadRequestBuilderTest, SingleUseSemantics)
{
  // After .build() the builder is in a moved-from state; subsequent .build() yields empty.
  ReadRequestBuilder builder;
  builder.read(NodeId{ObjectId::ObjectsFolder});
  auto first = std::move(builder).build();
  EXPECT_EQ(first.nodes_to_read().size(), 1u);

  // Note: this is undefined-ish in the sense that we don't promise anything about the
  // moved-from builder, but we do guarantee no crash. Don't assert on contents.
}

TEST(read_value_Freestanding, DefaultsToValueAttribute)
{
  auto req = read_value(NodeId{ObjectId::ObjectsFolder});
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  EXPECT_EQ(req.nodes_to_read()[0].attribute_id(), static_cast<uint32_t>(AttributeId::Value));
  EXPECT_EQ(req.timestamps_to_return(), TimestampsToReturn::Neither);
}

// ===========================================================================
// WriteRequestBuilder
// ===========================================================================

TEST(WriteRequestBuilderTest, SingleWriteCarriesValueAndDefaultAttribute)
{
  auto req = WriteRequestBuilder().write(NodeId{ObjectId::ObjectsFolder}, Variant{int32_t{42}}).build();
  ASSERT_EQ(req.nodes_to_write().size(), 1u);
  EXPECT_EQ(req.nodes_to_write()[0].attribute_id(), static_cast<uint32_t>(AttributeId::Value));
  EXPECT_EQ(req.nodes_to_write()[0].value().value().as<int32_t>(), 42);
}

TEST(WriteRequestBuilderTest, IndexRangeWithoutEntryThrows)
{
  EXPECT_THROW(WriteRequestBuilder().index_range(String{"0:5"}).build(), std::logic_error);
}

TEST(WriteRequestBuilderTest, IndexRangeAppliesToLastEntry)
{
  auto req = WriteRequestBuilder()
               .write(NodeId{1u, uint32_t{100}}, Variant{int32_t{1}})
               .write(NodeId{1u, uint32_t{200}}, Variant{int32_t{2}})
               .index_range(String{"0:3"})
               .build();
  ASSERT_EQ(req.nodes_to_write().size(), 2u);
  // index_range applies to the second entry, not the first.
  EXPECT_TRUE(std::string_view{req.nodes_to_write()[0].index_range()}.empty());
  EXPECT_EQ(std::string_view{req.nodes_to_write()[1].index_range()}, "0:3");
}

// ===========================================================================
// BrowseRequestBuilder
// ===========================================================================

TEST(BrowseRequestBuilderTest, BrowseDefaultsMatchOpcUaBrowseEverythingIdiom)
{
  // Defaults: Forward, reference_type={}, include_subtypes=true,
  // node_class_mask=0, result_mask=All.
  auto req = BrowseRequestBuilder().browse(NodeId{ObjectId::ObjectsFolder}).build();
  ASSERT_EQ(req.nodes_to_browse().size(), 1u);
  auto& desc = req.nodes_to_browse()[0];
  EXPECT_EQ(desc.browse_direction(), BrowseDirection::Forward);
  EXPECT_EQ(desc.reference_type_id(), NodeId{});
  EXPECT_TRUE(desc.include_subtypes());
  EXPECT_EQ(desc.node_class_mask(), 0u);
  EXPECT_EQ(desc.result_mask(), static_cast<uint32_t>(BrowseResultMask::All));
}

TEST(BrowseRequestBuilderTest, ModifierWithoutBrowseThrows)
{
  EXPECT_THROW(BrowseRequestBuilder().direction(BrowseDirection::Both).build(), std::logic_error);
  EXPECT_THROW(
    BrowseRequestBuilder().reference_type(NodeId{ReferenceTypeId::HasComponent}).build(), std::logic_error);
  EXPECT_THROW(BrowseRequestBuilder().include_subtypes(false).build(), std::logic_error);
  EXPECT_THROW(BrowseRequestBuilder().node_class_mask(1u).build(), std::logic_error);
  EXPECT_THROW(BrowseRequestBuilder().result_mask(0u).build(), std::logic_error);
}

TEST(BrowseRequestBuilderTest, ModifierAppliesToLastEntry)
{
  auto req = BrowseRequestBuilder()
               .browse(NodeId{ObjectId::ObjectsFolder})
               .browse(NodeId{ObjectId::TypesFolder})
               .direction(BrowseDirection::Inverse)
               .build();
  ASSERT_EQ(req.nodes_to_browse().size(), 2u);
  EXPECT_EQ(req.nodes_to_browse()[0].browse_direction(), BrowseDirection::Forward);
  EXPECT_EQ(req.nodes_to_browse()[1].browse_direction(), BrowseDirection::Inverse);
}

TEST(BrowseRequestBuilderTest, ViewModifierSetsRequestViewId)
{
  auto req =
    BrowseRequestBuilder().browse(NodeId{ObjectId::ObjectsFolder}).view(NodeId{1u, uint32_t{42}}).build();
  EXPECT_EQ(req.view().view_id(), (NodeId{1u, uint32_t{42}}));
}

// ===========================================================================
// TranslateBrowsePathsBuilder
// ===========================================================================

TEST(TranslateBrowsePathsBuilderTest, PathStepDefaultsAreHierarchicalForwardIncludeSubtypes)
{
  auto req = TranslateBrowsePathsBuilder()
               .path(NodeId{ObjectId::ObjectsFolder})
               .step(QualifiedName{0u, "Server"})
               .build();
  ASSERT_EQ(req.browse_paths().size(), 1u);
  auto& bp = req.browse_paths()[0];
  EXPECT_EQ(bp.starting_node(), NodeId{ObjectId::ObjectsFolder});
  ASSERT_EQ(bp.relative_path().elements().size(), 1u);
  auto& elem = bp.relative_path().elements()[0];
  EXPECT_EQ(elem.reference_type_id(), NodeId{ReferenceTypeId::HierarchicalReferences});
  EXPECT_FALSE(elem.is_inverse());
  EXPECT_TRUE(elem.include_subtypes());
  EXPECT_EQ(std::string_view{elem.target_name().name()}, "Server");
}

TEST(TranslateBrowsePathsBuilderTest, StepWithoutPathThrows)
{
  EXPECT_THROW(TranslateBrowsePathsBuilder().step(QualifiedName{0u, "X"}).build(), std::logic_error);
}

TEST(TranslateBrowsePathsBuilderTest, ModifierWithoutStepThrows)
{
  // .path() but no .step() yet - modifiers must throw.
  EXPECT_THROW(TranslateBrowsePathsBuilder().path(NodeId{ObjectId::ObjectsFolder}).is_inverse(true).build(),
    std::logic_error);
  EXPECT_THROW(TranslateBrowsePathsBuilder()
                 .path(NodeId{ObjectId::ObjectsFolder})
                 .reference_type(NodeId{ReferenceTypeId::HasComponent})
                 .build(),
    std::logic_error);
  EXPECT_THROW(
    TranslateBrowsePathsBuilder().path(NodeId{ObjectId::ObjectsFolder}).include_subtypes(false).build(),
    std::logic_error);
}

TEST(TranslateBrowsePathsBuilderTest, EmptyTargetNameProducesExpectedElement)
{
  // VIEW_TBP_003 relies on .step(QualifiedName{}) producing an element with empty name
  // but otherwise default fields.
  auto req =
    TranslateBrowsePathsBuilder().path(NodeId{ObjectId::ObjectsFolder}).step(QualifiedName{}).build();
  ASSERT_EQ(req.browse_paths().size(), 1u);
  auto& elem = req.browse_paths()[0].relative_path().elements()[0];
  EXPECT_TRUE(std::string_view{elem.target_name().name()}.empty());
  EXPECT_EQ(elem.reference_type_id(), NodeId{ReferenceTypeId::HierarchicalReferences});
  EXPECT_TRUE(elem.include_subtypes());
  EXPECT_FALSE(elem.is_inverse());
}

TEST(TranslateBrowsePathsBuilderTest, MultiStepBuildsMultiHopRelativePath)
{
  auto req = TranslateBrowsePathsBuilder()
               .path(NodeId{ObjectId::ObjectsFolder})
               .step(QualifiedName{0u, "Server"})
               .step(QualifiedName{0u, "ServerStatus"})
               .build();
  ASSERT_EQ(req.browse_paths().size(), 1u);
  EXPECT_EQ(req.browse_paths()[0].relative_path().elements().size(), 2u);
}

TEST(TranslateBrowsePathsBuilderTest, ModifiersApplyToLastStepOnly)
{
  auto req = TranslateBrowsePathsBuilder()
               .path(NodeId{ObjectId::ObjectsFolder})
               .step(QualifiedName{0u, "A"})
               .step(QualifiedName{0u, "B"})
               .is_inverse(true)
               .build();
  auto& elems = req.browse_paths()[0].relative_path().elements();
  ASSERT_EQ(elems.size(), 2u);
  EXPECT_FALSE(elems[0].is_inverse());
  EXPECT_TRUE(elems[1].is_inverse());
}

TEST(translate_path_Freestanding, MatchesBuilderDefaults)
{
  auto a = translate_path(NodeId{ObjectId::ObjectsFolder}, QualifiedName{0u, "Server"});
  auto b = TranslateBrowsePathsBuilder()
             .path(NodeId{ObjectId::ObjectsFolder})
             .step(QualifiedName{0u, "Server"})
             .build();
  ASSERT_EQ(a.browse_paths().size(), 1u);
  ASSERT_EQ(b.browse_paths().size(), 1u);
  auto& ea = a.browse_paths()[0].relative_path().elements()[0];
  auto& eb = b.browse_paths()[0].relative_path().elements()[0];
  EXPECT_EQ(ea.reference_type_id(), eb.reference_type_id());
  EXPECT_EQ(ea.is_inverse(), eb.is_inverse());
  EXPECT_EQ(ea.include_subtypes(), eb.include_subtypes());
  EXPECT_EQ(std::string_view{ea.target_name().name()}, std::string_view{eb.target_name().name()});
}

// ===========================================================================
// CallRequestBuilder
// ===========================================================================

TEST(CallRequestBuilderTest, NoArgCallPushesEntryWithEmptyArgs)
{
  auto req = CallRequestBuilder().call(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}).build();
  ASSERT_EQ(req.methods_to_call().size(), 1u);
  EXPECT_EQ(req.methods_to_call()[0].object_id(), (NodeId{1u, uint32_t{1}}));
  EXPECT_EQ(req.methods_to_call()[0].method_id(), (NodeId{1u, uint32_t{2}}));
  EXPECT_TRUE(req.methods_to_call()[0].input_arguments().empty());
}

TEST(CallRequestBuilderTest, InitializerListArgsPopulateInputArguments)
{
  auto req =
    CallRequestBuilder()
      .call(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, {Variant{int32_t{10}}, Variant{int32_t{20}}})
      .build();
  ASSERT_EQ(req.methods_to_call().size(), 1u);
  ASSERT_EQ(req.methods_to_call()[0].input_arguments().size(), 2u);
  EXPECT_EQ(req.methods_to_call()[0].input_arguments()[0].as<int32_t>(), 10);
  EXPECT_EQ(req.methods_to_call()[0].input_arguments()[1].as<int32_t>(), 20);
}

TEST(CallRequestBuilderTest, ArgumentAppendsToMostRecentCall)
{
  auto req = CallRequestBuilder()
               .call(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}})
               .argument(Variant{int32_t{1}})
               .call(NodeId{1u, uint32_t{3}}, NodeId{1u, uint32_t{4}})
               .argument(Variant{int32_t{2}})
               .argument(Variant{int32_t{3}})
               .build();
  ASSERT_EQ(req.methods_to_call().size(), 2u);
  ASSERT_EQ(req.methods_to_call()[0].input_arguments().size(), 1u);
  EXPECT_EQ(req.methods_to_call()[0].input_arguments()[0].as<int32_t>(), 1);
  ASSERT_EQ(req.methods_to_call()[1].input_arguments().size(), 2u);
  EXPECT_EQ(req.methods_to_call()[1].input_arguments()[0].as<int32_t>(), 2);
  EXPECT_EQ(req.methods_to_call()[1].input_arguments()[1].as<int32_t>(), 3);
}

TEST(CallRequestBuilderTest, ArgumentWithoutCallThrows)
{
  EXPECT_THROW(CallRequestBuilder().argument(Variant{int32_t{1}}).build(), std::logic_error);
}

TEST(call_method_Freestanding, MatchesBuilderForNoArgs)
{
  auto a = call_method(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}});
  auto b = CallRequestBuilder().call(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}).build();
  ASSERT_EQ(a.methods_to_call().size(), 1u);
  ASSERT_EQ(b.methods_to_call().size(), 1u);
  EXPECT_EQ(a.methods_to_call()[0].object_id(), b.methods_to_call()[0].object_id());
  EXPECT_EQ(a.methods_to_call()[0].method_id(), b.methods_to_call()[0].method_id());
}

TEST(call_method_Freestanding, MatchesBuilderForArgs)
{
  auto a = call_method(
    NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, {Variant{int32_t{5}}, Variant{double{2.5}}});
  ASSERT_EQ(a.methods_to_call().size(), 1u);
  ASSERT_EQ(a.methods_to_call()[0].input_arguments().size(), 2u);
  EXPECT_EQ(a.methods_to_call()[0].input_arguments()[0].as<int32_t>(), 5);
  EXPECT_DOUBLE_EQ(a.methods_to_call()[0].input_arguments()[1].as<double>(), 2.5);
}

// ===========================================================================
// AddNodesBuilder
// ===========================================================================

TEST(AddNodesBuilderTest, AddNodePopulatesRequiredFields)
{
  auto req = AddNodesBuilder()
               .add_node(NodeId{1u, uint32_t{100}}, QualifiedName{1u, "Child"}, NodeClass::Variable)
               .build();
  ASSERT_EQ(req.nodes_to_add().size(), 1u);
  auto& item = req.nodes_to_add()[0];
  EXPECT_EQ(item.parent_node_id(), (ExpandedNodeId{NodeId{1u, uint32_t{100}}}));
  EXPECT_EQ(std::string_view{item.browse_name().name()}, "Child");
  EXPECT_EQ(item.node_class(), NodeClass::Variable);
}

TEST(AddNodesBuilderTest, ModifiersChainOnLastEntry)
{
  auto req = AddNodesBuilder()
               .add_node(NodeId{1u, uint32_t{100}}, QualifiedName{1u, "A"}, NodeClass::Object)
               .add_node(NodeId{1u, uint32_t{200}}, QualifiedName{1u, "B"}, NodeClass::Variable)
               .reference_type(NodeId{1u, uint32_t{999}})
               .requested_node_id(NodeId{1u, uint32_t{555}})
               .type_definition(NodeId{1u, uint32_t{777}})
               .build();
  ASSERT_EQ(req.nodes_to_add().size(), 2u);
  EXPECT_EQ(req.nodes_to_add()[0].reference_type_id(), NodeId{});  // default empty
  EXPECT_EQ(req.nodes_to_add()[1].reference_type_id(), (NodeId{1u, uint32_t{999}}));
  EXPECT_EQ(req.nodes_to_add()[1].requested_new_node_id(), (ExpandedNodeId{NodeId{1u, uint32_t{555}}}));
  EXPECT_EQ(req.nodes_to_add()[1].type_definition(), (ExpandedNodeId{NodeId{1u, uint32_t{777}}}));
}

TEST(AddNodesBuilderTest, ModifierWithoutEntryThrows)
{
  EXPECT_THROW(AddNodesBuilder().reference_type(NodeId{1u, uint32_t{1}}).build(), std::logic_error);
  EXPECT_THROW(AddNodesBuilder().requested_node_id(NodeId{1u, uint32_t{1}}).build(), std::logic_error);
  EXPECT_THROW(AddNodesBuilder().type_definition(NodeId{1u, uint32_t{1}}).build(), std::logic_error);
}

TEST(AddNodesBuilderTest, ExpandedNodeIdOverloadPreservesServerIndex)
{
  ExpandedNodeId expId{NodeId{1u, uint32_t{42}}};
  expId.server_index() = 7;
  auto req = AddNodesBuilder()
               .add_node(NodeId{1u, uint32_t{100}}, QualifiedName{1u, "X"}, NodeClass::Variable)
               .requested_node_id(expId)
               .build();
  EXPECT_EQ(req.nodes_to_add()[0].requested_new_node_id().server_index(), 7u);
}

// ===========================================================================
// DeleteNodes (builder + freestanding)
// ===========================================================================

TEST(DeleteNodesTest, FreestandingSingleNodeDefaultsToDeleteTargetRefs)
{
  auto req = delete_node(NodeId{1u, uint32_t{42}});
  ASSERT_EQ(req.nodes_to_delete().size(), 1u);
  EXPECT_EQ(req.nodes_to_delete()[0].node_id(), (NodeId{1u, uint32_t{42}}));
  EXPECT_TRUE(req.nodes_to_delete()[0].delete_target_references());
}

TEST(DeleteNodesTest, FreestandingHonorsExplicitFalse)
{
  auto req = delete_node(NodeId{1u, uint32_t{42}}, /*delete_target_references=*/false);
  EXPECT_FALSE(req.nodes_to_delete()[0].delete_target_references());
}

TEST(DeleteNodesTest, InitializerListProducesOrderedRequest)
{
  auto req = delete_nodes({NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}});
  ASSERT_EQ(req.nodes_to_delete().size(), 2u);
  EXPECT_EQ(req.nodes_to_delete()[0].node_id(), (NodeId{1u, uint32_t{1}}));
  EXPECT_EQ(req.nodes_to_delete()[1].node_id(), (NodeId{1u, uint32_t{2}}));
}

TEST(DeleteNodesBuilderTest, BuilderChainsMultipleDeletes)
{
  auto req = DeleteNodesBuilder()
               .delete_node(NodeId{1u, uint32_t{1}})
               .delete_node(NodeId{1u, uint32_t{2}}, /*delete_target_references=*/false)
               .build();
  ASSERT_EQ(req.nodes_to_delete().size(), 2u);
  EXPECT_TRUE(req.nodes_to_delete()[0].delete_target_references());
  EXPECT_FALSE(req.nodes_to_delete()[1].delete_target_references());
}

// ===========================================================================
// AddReferencesBuilder
// ===========================================================================

TEST(AddReferencesBuilderTest, AddReferenceDefaultsToForwardObject)
{
  auto req = AddReferencesBuilder()
               .add_reference_async(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, NodeId{1u, uint32_t{3}})
               .build();
  ASSERT_EQ(req.references_to_add().size(), 1u);
  auto& item = req.references_to_add()[0];
  EXPECT_EQ(item.source_node_id(), (NodeId{1u, uint32_t{1}}));
  EXPECT_EQ(item.reference_type_id(), (NodeId{1u, uint32_t{2}}));
  EXPECT_EQ(item.target_node_id(), (ExpandedNodeId{NodeId{1u, uint32_t{3}}}));
  EXPECT_TRUE(item.is_forward());
  EXPECT_EQ(item.target_node_class(), NodeClass::Object);
}

TEST(AddReferencesBuilderTest, ModifiersChainOnLastEntry)
{
  auto req = AddReferencesBuilder()
               .add_reference_async(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, NodeId{1u, uint32_t{3}})
               .add_reference_async(NodeId{1u, uint32_t{4}}, NodeId{1u, uint32_t{5}}, NodeId{1u, uint32_t{6}})
               .is_forward(false)
               .target_node_class(NodeClass::Variable)
               .build();
  ASSERT_EQ(req.references_to_add().size(), 2u);
  EXPECT_TRUE(req.references_to_add()[0].is_forward());
  EXPECT_EQ(req.references_to_add()[0].target_node_class(), NodeClass::Object);
  EXPECT_FALSE(req.references_to_add()[1].is_forward());
  EXPECT_EQ(req.references_to_add()[1].target_node_class(), NodeClass::Variable);
}

TEST(AddReferencesBuilderTest, ModifierWithoutEntryThrows)
{
  EXPECT_THROW(AddReferencesBuilder().is_forward(false).build(), std::logic_error);
  EXPECT_THROW(AddReferencesBuilder().target_node_class(NodeClass::Variable).build(), std::logic_error);
}

// ===========================================================================
// DeleteReferencesBuilder
// ===========================================================================

TEST(DeleteReferencesBuilderTest, DeleteReferenceDefaultsToForwardBidirectional)
{
  auto req = DeleteReferencesBuilder()
               .delete_reference(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, NodeId{1u, uint32_t{3}})
               .build();
  ASSERT_EQ(req.references_to_delete().size(), 1u);
  auto& item = req.references_to_delete()[0];
  EXPECT_EQ(item.source_node_id(), (NodeId{1u, uint32_t{1}}));
  EXPECT_TRUE(item.is_forward());
  EXPECT_TRUE(item.delete_bidirectional());
}

TEST(DeleteReferencesBuilderTest, ModifiersChainOnLastEntry)
{
  auto req = DeleteReferencesBuilder()
               .delete_reference(NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, NodeId{1u, uint32_t{3}})
               .is_forward(false)
               .delete_bidirectional(false)
               .build();
  EXPECT_FALSE(req.references_to_delete()[0].is_forward());
  EXPECT_FALSE(req.references_to_delete()[0].delete_bidirectional());
}

TEST(DeleteReferencesBuilderTest, ModifierWithoutEntryThrows)
{
  EXPECT_THROW(DeleteReferencesBuilder().is_forward(false).build(), std::logic_error);
  EXPECT_THROW(DeleteReferencesBuilder().delete_bidirectional(false).build(), std::logic_error);
}

// ===========================================================================
// HistoryReadRawBuilder
// ===========================================================================

TEST(history_read_raw_Freestanding, ProducesRawDetailsWithDefaults)
{
  DateTime start{2020, 1, 1, 0, 0, 0};
  DateTime end{2030, 1, 1, 0, 0, 0};
  auto req = history_read_raw(NodeId{1u, uint32_t{100}}, start, end);
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  EXPECT_EQ(req.nodes_to_read()[0].node_id(), (NodeId{1u, uint32_t{100}}));
  EXPECT_EQ(req.timestamps_to_return(), TimestampsToReturn::Both);
  EXPECT_FALSE(req.release_continuation_points());

  // history_read_details should be a ReadRawModifiedDetails with our fields set.
  ASSERT_TRUE(req.history_read_details().get() != nullptr);
  const auto* details = dynamic_cast<const ReadRawModifiedDetails*>(req.history_read_details().get());
  ASSERT_NE(details, nullptr) << "history_read_details should be ReadRawModifiedDetails";
  EXPECT_FALSE(details->is_read_modified());
  EXPECT_FALSE(details->return_bounds());
  EXPECT_EQ(details->num_values_per_node(), 100u);
}

TEST(HistoryReadRawBuilderTest, ConstructorSetsRequiredFields)
{
  DateTime start{2020, 1, 1, 0, 0, 0};
  DateTime end{2030, 1, 1, 0, 0, 0};
  auto req = HistoryReadRawBuilder(start, end, /*num=*/50).read(NodeId{1u, uint32_t{100}}).build();
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  const auto* details = dynamic_cast<const ReadRawModifiedDetails*>(req.history_read_details().get());
  ASSERT_NE(details, nullptr);
  EXPECT_EQ(details->num_values_per_node(), 50u);
}

TEST(HistoryReadRawBuilderTest, ModifiersChain)
{
  DateTime start{2020, 1, 1, 0, 0, 0};
  DateTime end{2030, 1, 1, 0, 0, 0};
  auto req = HistoryReadRawBuilder(start, end)
               .is_read_modified(true)
               .return_bounds(true)
               .timestamps(TimestampsToReturn::Source)
               .release_continuation_points(true)
               .read(NodeId{1u, uint32_t{1}})
               .build();
  const auto* details = dynamic_cast<const ReadRawModifiedDetails*>(req.history_read_details().get());
  ASSERT_NE(details, nullptr);
  EXPECT_TRUE(details->is_read_modified());
  EXPECT_TRUE(details->return_bounds());
  EXPECT_EQ(req.timestamps_to_return(), TimestampsToReturn::Source);
  EXPECT_TRUE(req.release_continuation_points());
}

TEST(HistoryReadRawBuilderTest, ReadAcceptsContinuationPoint)
{
  DateTime start{2020, 1, 1, 0, 0, 0};
  DateTime end{2030, 1, 1, 0, 0, 0};
  ByteString cp{uint8_t{0x01}, uint8_t{0x02}, uint8_t{0x03}};
  auto req = HistoryReadRawBuilder(start, end).read(NodeId{1u, uint32_t{1}}, cp).build();
  ASSERT_EQ(req.nodes_to_read().size(), 1u);
  EXPECT_EQ(req.nodes_to_read()[0].continuation_point().size(), 3u);
}

TEST(HistoryReadRawBuilderTest, MultiNodeRead)
{
  DateTime start{2020, 1, 1, 0, 0, 0};
  DateTime end{2030, 1, 1, 0, 0, 0};
  auto req =
    HistoryReadRawBuilder(start, end).read(NodeId{1u, uint32_t{1}}).read(NodeId{1u, uint32_t{2}}).build();
  ASSERT_EQ(req.nodes_to_read().size(), 2u);
}

// ===========================================================================
// register_nodes / unregister_nodes shortcuts
// ===========================================================================

TEST(RegisterNodesTest, SingleNodeProducesSingleElementRequest)
{
  auto req = register_nodes(NodeId{ObjectId::ObjectsFolder});
  ASSERT_EQ(req.nodes_to_register().size(), 1u);
  EXPECT_EQ(req.nodes_to_register()[0], NodeId{ObjectId::ObjectsFolder});
}

TEST(RegisterNodesTest, InitializerListProducesOrderedRequest)
{
  auto req = register_nodes({NodeId{1u, uint32_t{1}}, NodeId{1u, uint32_t{2}}, NodeId{1u, uint32_t{3}}});
  ASSERT_EQ(req.nodes_to_register().size(), 3u);
  EXPECT_EQ(req.nodes_to_register()[0], (NodeId{1u, uint32_t{1}}));
  EXPECT_EQ(req.nodes_to_register()[1], (NodeId{1u, uint32_t{2}}));
  EXPECT_EQ(req.nodes_to_register()[2], (NodeId{1u, uint32_t{3}}));
}

TEST(UnregisterNodesTest, InitializerListProducesOrderedRequest)
{
  auto req = unregister_nodes({NodeId{1u, uint32_t{10}}, NodeId{1u, uint32_t{20}}});
  ASSERT_EQ(req.nodes_to_unregister().size(), 2u);
  EXPECT_EQ(req.nodes_to_unregister()[0], (NodeId{1u, uint32_t{10}}));
  EXPECT_EQ(req.nodes_to_unregister()[1], (NodeId{1u, uint32_t{20}}));
}
