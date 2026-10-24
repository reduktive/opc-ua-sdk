// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_INTEGRATION_HELPERS_REQUESTS_H
#define UA_INTEGRATION_HELPERS_REQUESTS_H

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_request.h"
#include "ua_browse_result_mask.h"
#include "ua_continuation_point.h"
#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_browse_path.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_date_time.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_expanded_node_id.h"
#include "ua_history_read_request.h"
#include "ua_history_read_value_id.h"
#include "ua_node_class.h"
#include "ua_read_raw_modified_details.h"
#include "ua_register_nodes_request.h"
#include "ua_relative_path_element.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_unregister_nodes_request.h"
#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_string.h"
#include "ua_timestamps_to_return.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_value.h"

#include <cstdint>
#include <initializer_list>
#include <memory>

namespace ua
{
namespace client
{
class Session;
}
}  // namespace ua

namespace ua::test_helpers
{

// ---------------------------------------------------------------------------
// Freestanding shortcuts
//
// 80% of read requests are "read one attribute of one node, default timestamps":
//   auto resp = session.attributes().read_sync(read_value(node));
//   auto resp = session.attributes().read_sync(read_value(node, AttributeId::DisplayName));
//
// For one attribute across many nodes:
//   auto resp = session.attributes().read_sync(
//       read_values({nodeA, nodeB, nodeC}));
//
// timestamps() defaults to Neither because that is the most common test
// shape; pass TimestampsToReturn explicitly when timestamps matter.
// ---------------------------------------------------------------------------

ua::ReadRequest read_value(const ua::NodeId& node, ua::AttributeId attr = ua::AttributeId::Value,
  ua::TimestampsToReturn timestamps = ua::TimestampsToReturn::Neither);

ua::ReadRequest read_values(std::initializer_list<ua::NodeId> nodes,
  ua::AttributeId attr = ua::AttributeId::Value,
  ua::TimestampsToReturn timestamps = ua::TimestampsToReturn::Neither);

// ---------------------------------------------------------------------------
// ReadRequestBuilder - fluent builder for multi-entry or non-default reads
//
//   auto req = ReadRequestBuilder()
//                  .read(node).attributes({AttributeId::Value, AttributeId::DisplayName})
//                  .read(otherNode).attribute(AttributeId::BrowseName)
//                  .timestamps(TimestampsToReturn::Source)
//                  .max_age(5000.0);
//
//   // Direct pass - implicit conversion (move-only):
//   auto resp = session.attributes().read_sync(
//                  ReadRequestBuilder().read(node).attribute(AttributeId::Value));
//
//   // Or explicit .build() when you want to inspect/modify before sending:
//   auto req = ReadRequestBuilder().read(node).attribute(AttributeId::Value).build();
//
// Modifiers (data_encoding, index_range) apply to the most-recently-added
// nodes_to_read entry.
//
// ## Semantics - read this before using the builder
//
// - **Single-use.** `build()` and the implicit `operator ReadRequest()` MOVE the
//   internal state out. Calling them twice yields an empty request the second time.
//   Construct a fresh builder per request.
//
// - **`.read(node)` starts a new pending entry** with attribute=Value as a
//   placeholder. The pending entry is materialised on the next call that needs it
//   (either implicitly when another `.read()` arrives, or explicitly by `.build()`).
//
// - **`.attribute(attr)` sets the pending entry's attribute.** Back-to-back
//   `.attribute()` calls OVERWRITE the pending attribute, they do NOT add new entries:
//
//     .read(B).attribute(X).attribute(Y)   // -> B.Y      (X is overwritten)
//
//   For multiple attributes on one node, use `.attributes({A, B, C})`:
//
//     .read(B).attributes({X, Y, Z})       // -> B.X, B.Y, B.Z
//
//   For one attribute per node, alternate `.read()` and `.attribute()`:
//
//     .read(A).attribute(X).read(B).attribute(Y)   // -> A.X, B.Y
//
//   There is one corner case: calling `.attribute(Z)` AFTER a `.attributes({...})`
//   (which flushed everything and left no pending) creates a new pending entry on
//   the same node as the last flushed entry:
//
//     .read(A).attributes({X, Y}).attribute(Z)     // -> A.X, A.Y, A.Z
//
// - **`.attributes({A,B,C})` DISCARDS the pending Value placeholder** and adds
//   N new entries on the current node. Without the discard, `.read(node).attributes({A,B})`
//   would produce 3 entries (Value + A + B) instead of 2 - a bug I caught during
//   the first migration. Do not change this behaviour without re-running the
//   compliance_attribute_read sweep.
//
// - **Modifiers (`data_encoding`, `index_range`) apply to the pending entry**, or
//   to the last-added entry if no pending exists. Calling them with neither
//   raises a programming error (std::logic_error).
// ---------------------------------------------------------------------------

class ReadRequestBuilder
{
public:
  ReadRequestBuilder& read(const ua::NodeId& node);

  ReadRequestBuilder& attribute(ua::AttributeId attr);
  ReadRequestBuilder& attributes(std::initializer_list<ua::AttributeId> attrs);

  ReadRequestBuilder& data_encoding(ua::QualifiedName encoding);
  ReadRequestBuilder& index_range(ua::String range);

  ReadRequestBuilder& timestamps(ua::TimestampsToReturn timestamps);
  ReadRequestBuilder& max_age(double maxAgeMs);

  // Single-use: moves internal state out. Calling build()/conversion again on the
  // same builder yields an empty request.
  ua::ReadRequest build();
  operator ua::ReadRequest();

private:
  ua::ReadRequest mRequest{};
  ua::ReadValueId mPending{};
  bool mHasPending{false};
  ua::AttributeId mLastAttribute{ua::AttributeId::Value};

  void flush_pending();
  ua::ReadValueId& mutate_last();
};

// ---------------------------------------------------------------------------
// WriteRequestBuilder - fluent builder for writes.
//
//   auto req = WriteRequestBuilder()
//                  .write(node, ua::Variant{int32_t{42}})
//                  .write(otherNode, ua::DataValue{ua::Variant{double{3.14}}});
//
// ## Semantics
//
// - **Single-use**, same as ReadRequestBuilder.
// - **No pending state** - each `.write()` pushes a complete entry immediately.
//   This is simpler than the Read builder; there is no flush phase.
// - **`.index_range(...)` mutates the entry pushed by the immediately preceding
//   `.write()`**. Calling it with no entries throws std::logic_error.
// ---------------------------------------------------------------------------

class WriteRequestBuilder
{
public:
  WriteRequestBuilder& write(
    const ua::NodeId& node, ua::Variant value, ua::AttributeId attr = ua::AttributeId::Value);
  WriteRequestBuilder& write(
    const ua::NodeId& node, ua::DataValue value, ua::AttributeId attr = ua::AttributeId::Value);

  // Modifies the most-recently-added entry.
  WriteRequestBuilder& index_range(ua::String range);

  // Single-use; see ReadRequestBuilder::build.
  ua::WriteRequest build();
  operator ua::WriteRequest();

private:
  ua::WriteRequest mRequest{};
};

// ---------------------------------------------------------------------------
// write_value - common-case helper for tests that just need to set a value.
//
// Sends a single-attribute write via the session. On failure (service-level or
// per-result), records a non-fatal gtest failure with diagnostic detail. Tests
// that exercise write behavior itself should use WriteRequestBuilder + matchers.
// ---------------------------------------------------------------------------

void write_value_async(ua::client::Session& session, const ua::NodeId& node, ua::DataValue value);
void write_value_async(ua::client::Session& session, const ua::NodeId& node, ua::Variant value);

// ---------------------------------------------------------------------------
// Browse - shortcuts + builder
//
// Default browse semantics match the OPC UA "browse everything from this node"
// idiom: direction=Forward, reference_type={} (matches all), include_subtypes=true,
// node_class_mask=0 (all classes), result_mask=BrowseResultMask::All. The builder
// modifiers below override these per-entry.
//
//   // Trivial: browse forward, all references:
//   auto resp = session.view().browse_sync(browse(node));
//
//   // Multi-node with filters:
//   auto resp = session.view().browse_sync(
//       BrowseRequestBuilder()
//           .browse(folderA).node_class_mask(static_cast<uint32_t>(NodeClass::Variable))
//           .browse(folderB).reference_type(NodeId{ReferenceTypeId::HasComponent}).include_subtypes(false)
//           .max_references_per_node(50));
//
//   // BrowseNext (continue a paginated browse):
//   auto resp = session.view().browse_next_sync(browse_next(cp));
//   auto resp = session.view().browse_next_sync(browse_next(cp, /*release=*/true));
//
// Same single-use semantics as the read/write builders.
// ---------------------------------------------------------------------------

ua::BrowseRequest browse(const ua::NodeId& node);

ua::BrowseNextRequest browse_next(ua::ContinuationPoint cp, bool release = false);
ua::BrowseNextRequest browse_next(std::initializer_list<ua::ContinuationPoint> cps, bool release = false);

class BrowseRequestBuilder
{
public:
  // Adds a new BrowseDescription entry on `node` with the default semantics
  // described above. Subsequent modifiers apply to this entry.
  BrowseRequestBuilder& browse(const ua::NodeId& node);

  // Modifiers on the most-recently-added entry.
  BrowseRequestBuilder& direction(ua::BrowseDirection dir);
  BrowseRequestBuilder& reference_type(const ua::NodeId& refType);
  BrowseRequestBuilder& include_subtypes(bool yes = true);
  BrowseRequestBuilder& node_class_mask(uint32_t mask);
  BrowseRequestBuilder& result_mask(uint32_t mask);

  // Request-level options.
  BrowseRequestBuilder& max_references_per_node(uint32_t n);
  BrowseRequestBuilder& view(const ua::NodeId& viewId);

  // Single-use; see ReadRequestBuilder::build.
  ua::BrowseRequest build();
  operator ua::BrowseRequest();

private:
  ua::BrowseRequest mRequest{};

  ua::BrowseDescription& mutate_last();
};

// ---------------------------------------------------------------------------
// RegisterNodes / UnregisterNodes - freestanding shortcuts
//
// Both requests are just an Array<NodeId>; no per-node configuration. No builder
// needed.
//
//   auto resp = session.view().register_nodes_sync(register_nodes(node));
//   auto resp = session.view().register_nodes_sync(register_nodes({nodeA, nodeB}));
//   auto resp = session.view().unregister_nodes_sync(unregister_nodes(registeredId));
// ---------------------------------------------------------------------------

ua::RegisterNodesRequest register_nodes(const ua::NodeId& node);
ua::RegisterNodesRequest register_nodes(std::initializer_list<ua::NodeId> nodes);

ua::UnregisterNodesRequest unregister_nodes(const ua::NodeId& node);
ua::UnregisterNodesRequest unregister_nodes(std::initializer_list<ua::NodeId> nodes);

// ---------------------------------------------------------------------------
// TranslateBrowsePathsToNodeIds - shortcut + builder
//
// The request shape is a list of BrowsePaths, each containing a starting_node
// and a RelativePath (sequence of RelativePathElements). Defaults for a step:
//   reference_type_id = HierarchicalReferences
//   is_inverse        = false
//   include_subtypes  = true
//
//   // Single-hop with default ref type / forward / include_subtypes:
//   auto resp = session.view().translate_browse_paths_sync(
//                  translate_path(start, QualifiedName{ns, "Child"}));
//
//   // Multi-hop / non-default ref type:
//   auto resp = session.view().translate_browse_paths_sync(
//                  TranslateBrowsePathsBuilder()
//                      .path(start)
//                          .step(QualifiedName{ns, "Folder"})
//                          .step(QualifiedName{ns,
//                          "Var"}).reference_type(NodeId{ReferenceTypeId::HasComponent})
//                      .path(otherStart)
//                          .step(QualifiedName{ns, "Parent"}).is_inverse());
//
// ## Semantics
// - **Single-use**, same as the other builders.
// - **`.path(start_node)` pushes a new BrowsePath** with an empty relative_path.
// - **`.step(target_name)` pushes a RelativePathElement onto the most-recent
//   path's relative_path** with the defaults above. Calling `.step()` with no
//   prior `.path()` throws std::logic_error.
// - **`.reference_type(...) / .is_inverse(...) / .include_subtypes(...)`
//   mutate the most-recently-pushed step.** Calling them with no step throws.
// ---------------------------------------------------------------------------

ua::TranslateBrowsePathsToNodeIdsRequest translate_path(
  const ua::NodeId& startNode, const ua::QualifiedName& targetName);

class TranslateBrowsePathsBuilder
{
public:
  TranslateBrowsePathsBuilder& path(const ua::NodeId& startNode);
  TranslateBrowsePathsBuilder& step(const ua::QualifiedName& targetName);

  TranslateBrowsePathsBuilder& reference_type(const ua::NodeId& refTypeId);
  TranslateBrowsePathsBuilder& is_inverse(bool yes = true);
  TranslateBrowsePathsBuilder& include_subtypes(bool yes = true);

  // Single-use; see ReadRequestBuilder::build.
  ua::TranslateBrowsePathsToNodeIdsRequest build();
  operator ua::TranslateBrowsePathsToNodeIdsRequest();

private:
  ua::TranslateBrowsePathsToNodeIdsRequest mRequest{};

  ua::BrowsePath& mutate_last_path();
  ua::RelativePathElement& mutate_last_step();
};

// ---------------------------------------------------------------------------
// Call (method service set) - shortcut + builder
//
// Each method call is (object_id, method_id, input_arguments[]).
//
//   // No-args trivial case:
//   auto resp = session.methods().call_sync(call_method(obj, method));
//
//   // With args in one shot:
//   auto resp = session.methods().call_sync(
//                  call_method(obj, method, {ua::Variant{int32_t{1}}, ua::Variant{2.5}}));
//
//   // Multi-call (rare):
//   auto resp = session.methods().call_sync(
//                  CallRequestBuilder()
//                      .call(objA, methodA, {ua::Variant{1}})
//                      .call(objB, methodB).argument(ua::Variant{2}));
//
// ## Semantics
// - **Single-use.** Same as the other builders.
// - **`.call(obj, method)` pushes a new CallMethodRequest entry** with empty
//   input_arguments. `.call(obj, method, {args...})` is equivalent to
//   `.call(obj, method)` followed by per-arg `.argument()` calls.
// - **`.argument(value)` appends one Variant to the most-recently-pushed call's
//   input_arguments.** Throws std::logic_error if no call has been pushed.
// ---------------------------------------------------------------------------

ua::CallRequest call_method(const ua::NodeId& objectId, const ua::NodeId& methodId);
ua::CallRequest call_method(
  const ua::NodeId& objectId, const ua::NodeId& methodId, std::initializer_list<ua::Variant> args);

class CallRequestBuilder
{
public:
  CallRequestBuilder& call(const ua::NodeId& objectId, const ua::NodeId& methodId);
  CallRequestBuilder& call(
    const ua::NodeId& objectId, const ua::NodeId& methodId, std::initializer_list<ua::Variant> args);

  CallRequestBuilder& argument(ua::Variant value);

  // Single-use; see ReadRequestBuilder::build.
  ua::CallRequest build();
  operator ua::CallRequest();

private:
  ua::CallRequest mRequest{};

  ua::CallMethodRequest& mutate_last();
};

// ---------------------------------------------------------------------------
// NodeManagement - AddNodes / DeleteNodes / AddReferences / DeleteReferences
//
// Four separate builders (per PR 6 review): each item type has a distinct shape
// and an omnibus builder would expose item-type-specific modifiers that are only
// legal on a matching item. One builder per request type keeps misuse at compile
// time, not runtime.
//
// All four follow the same pattern as Browse/Call builders: a primary push verb,
// chained modifiers on the most-recently-pushed entry, single-use semantics,
// throw on modifier-without-entry.
// ---------------------------------------------------------------------------

// AddNodes -----------------------------------------------------------------

class AddNodesBuilder
{
public:
  // Push an AddNodesItem with these required fields. Modifiers below mutate it.
  // Common idiom:
  //   AddNodesBuilder()
  //       .add_node(parentId, browseName, NodeClass::Variable)
  //       .reference_type(NodeId{ReferenceTypeId::HasComponent})
  //       .requested_node_id(NodeId{ns, 9001})
  //       .type_definition(NodeId{VariableTypeId::BaseDataVariableType});
  AddNodesBuilder& add_node(
    const ua::NodeId& parentNodeId, const ua::QualifiedName& browseName, ua::NodeClass nodeClass);

  // Modifiers on the most-recently-added entry:
  AddNodesBuilder& reference_type(const ua::NodeId& refTypeId);
  AddNodesBuilder& requested_node_id(const ua::NodeId& id);
  AddNodesBuilder& requested_node_id(const ua::ExpandedNodeId& id);
  AddNodesBuilder& type_definition(const ua::NodeId& td);
  AddNodesBuilder& type_definition(const ua::ExpandedNodeId& td);

  // Single-use; see ReadRequestBuilder::build.
  ua::AddNodesRequest build();
  operator ua::AddNodesRequest();

private:
  ua::AddNodesRequest mRequest{};

  ua::AddNodesItem& mutate_last();
};

// DeleteNodes --------------------------------------------------------------

// Freestanding: most tests delete a single node with delete_target_references=true.
ua::DeleteNodesRequest delete_node(const ua::NodeId& id, bool deleteTargetReferences = true);
ua::DeleteNodesRequest delete_nodes(
  std::initializer_list<ua::NodeId> ids, bool deleteTargetReferences = true);

class DeleteNodesBuilder
{
public:
  DeleteNodesBuilder& delete_node(const ua::NodeId& id, bool deleteTargetReferences = true);

  ua::DeleteNodesRequest build();
  operator ua::DeleteNodesRequest();

private:
  ua::DeleteNodesRequest mRequest{};
};

// AddReferences ------------------------------------------------------------

class AddReferencesBuilder
{
public:
  // Push an AddReferencesItem with the three required fields. Defaults:
  //   is_forward = true, target_node_class = Object, target_server_uri = empty.
  AddReferencesBuilder& add_reference_async(
    const ua::NodeId& source, const ua::NodeId& referenceType, const ua::NodeId& target);

  // Modifiers on the most-recently-added entry:
  AddReferencesBuilder& is_forward(bool yes = true);
  AddReferencesBuilder& target_node_class(ua::NodeClass nc);
  AddReferencesBuilder& target_server_uri(ua::String uri);

  ua::AddReferencesRequest build();
  operator ua::AddReferencesRequest();

private:
  ua::AddReferencesRequest mRequest{};

  ua::AddReferencesItem& mutate_last();
};

// DeleteReferences ---------------------------------------------------------

class DeleteReferencesBuilder
{
public:
  // Push a DeleteReferencesItem. Defaults: is_forward=true, delete_bidirectional=true.
  DeleteReferencesBuilder& delete_reference(
    const ua::NodeId& source, const ua::NodeId& referenceType, const ua::NodeId& target);

  // Modifiers on the most-recently-added entry:
  DeleteReferencesBuilder& is_forward(bool yes = true);
  DeleteReferencesBuilder& delete_bidirectional(bool yes = true);

  ua::DeleteReferencesRequest build();
  operator ua::DeleteReferencesRequest();

private:
  ua::DeleteReferencesRequest mRequest{};

  ua::DeleteReferencesItem& mutate_last();
};

// ---------------------------------------------------------------------------
// HistoryRead - raw/modified details
//
// Only HistoryReadRawBuilder is implemented today; the three other detail types
// (ReadEventDetails, ReadProcessedDetails, ReadAtTimeDetails) follow the same
// pattern and can be added when a compliance test needs them. Per PR 7
// reviewer advice: one builder per details type rather than an omnibus.
//
//   // Single node, default timestamps=Both, 100 values:
//   auto resp = session.attributes().history_read_sync(
//                  history_read_raw(node, start, end));
//
//   // Modified values flag, custom range, release continuation:
//   auto resp = session.attributes().history_read_sync(
//                  HistoryReadRawBuilder(start, end, /*num=*/1)
//                      .is_read_modified(true)
//                      .read(node));
//
//   // Continue from a previously-returned continuation point:
//   auto resp = session.attributes().history_read_sync(
//                  HistoryReadRawBuilder(start, end).read(node, cp));
// ---------------------------------------------------------------------------

ua::HistoryReadRequest history_read_raw(const ua::NodeId& node, const ua::DateTime& start,
  const ua::DateTime& end, uint32_t numValuesPerNode = 100);

class HistoryReadRawBuilder
{
public:
  // Required fields are in the constructor; sensible defaults for the rest.
  // Defaults: is_read_modified=false, return_bounds=false,
  // timestamps_to_return=Both, release_continuation_points=false.
  HistoryReadRawBuilder(const ua::DateTime& start, const ua::DateTime& end, uint32_t numValuesPerNode = 100);

  // Request-level modifiers.
  HistoryReadRawBuilder& is_read_modified(bool yes = true);
  HistoryReadRawBuilder& return_bounds(bool yes = true);
  HistoryReadRawBuilder& timestamps(ua::TimestampsToReturn ts);
  HistoryReadRawBuilder& release_continuation_points(bool yes = true);

  // Node entries.
  HistoryReadRawBuilder& read(const ua::NodeId& node);
  HistoryReadRawBuilder& read(const ua::NodeId& node, ua::ContinuationPoint cp);

  // Single-use; see ReadRequestBuilder::build.
  ua::HistoryReadRequest build();
  operator ua::HistoryReadRequest();

private:
  ua::HistoryReadRequest mRequest{};
  // The details unique_ptr is created in the ctor and moved into the request at build().
  // Modifiers below act on this unique_ptr so they can be chained before any .read() call.
  std::unique_ptr<ua::ReadRawModifiedDetails> mDetails;
};

}  // namespace ua::test_helpers

#endif  // UA_INTEGRATION_HELPERS_REQUESTS_H
