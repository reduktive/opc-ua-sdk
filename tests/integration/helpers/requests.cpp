// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "requests.h"

#include "ua_browse_result_mask.h"
#include "ua_client_session.h"
#include "ua_referencetype_id.h"
#include "ua_session_attribute_services.h"
#include "ua_write_response.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace ua::test_helpers
{

namespace
{

ua::ReadValueId make_read_value_id(const ua::NodeId& node, ua::AttributeId attr)
{
  ua::ReadValueId rv;
  rv.node_id() = node;
  rv.attribute_id() = static_cast<uint32_t>(attr);
  return rv;
}

ua::WriteValue make_write_value(const ua::NodeId& node, ua::AttributeId attr, ua::DataValue value)
{
  ua::WriteValue wv;
  wv.node_id() = node;
  wv.attribute_id() = static_cast<uint32_t>(attr);
  wv.value() = std::move(value);
  return wv;
}

}  // namespace

// ---------------------------------------------------------------------------
// Freestanding shortcuts
// ---------------------------------------------------------------------------

ua::ReadRequest read_value(const ua::NodeId& node, ua::AttributeId attr, ua::TimestampsToReturn timestamps)
{
  ua::ReadRequest req;
  req.timestamps_to_return() = timestamps;
  req.nodes_to_read().push_back(make_read_value_id(node, attr));
  return req;
}

ua::ReadRequest read_values(
  std::initializer_list<ua::NodeId> nodes, ua::AttributeId attr, ua::TimestampsToReturn timestamps)
{
  ua::ReadRequest req;
  req.timestamps_to_return() = timestamps;
  for (const auto& node : nodes)
  {
    req.nodes_to_read().push_back(make_read_value_id(node, attr));
  }
  return req;
}

// ---------------------------------------------------------------------------
// ReadRequestBuilder
// ---------------------------------------------------------------------------

ReadRequestBuilder& ReadRequestBuilder::read(const ua::NodeId& node)
{
  flush_pending();
  mPending = make_read_value_id(node, ua::AttributeId::Value);
  mHasPending = true;
  mLastAttribute = ua::AttributeId::Value;
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::attribute(ua::AttributeId attr)
{
  if (mHasPending)
  {
    mPending.attribute_id() = static_cast<uint32_t>(attr);
    mLastAttribute = attr;
  }
  else if (!mRequest.nodes_to_read().empty())
  {
    // .attribute() after a previous flush: re-target the last node with a new attribute entry.
    auto& last = mRequest.nodes_to_read()[mRequest.nodes_to_read().size() - 1];
    mPending = make_read_value_id(last.node_id(), attr);
    mHasPending = true;
    mLastAttribute = attr;
  }
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::attributes(std::initializer_list<ua::AttributeId> attrs)
{
  // attributes({...}) replaces the pending entry entirely with N new entries on the
  // same node. Without this, the pending (default-Value) entry would be flushed too,
  // giving N+1 results.
  ua::NodeId currentNode;
  if (mHasPending)
  {
    currentNode = mPending.node_id();
    mPending = ua::ReadValueId{};
    mHasPending = false;
  }
  else if (!mRequest.nodes_to_read().empty())
  {
    currentNode = mRequest.nodes_to_read()[mRequest.nodes_to_read().size() - 1].node_id();
  }
  for (auto attr : attrs)
  {
    mRequest.nodes_to_read().push_back(make_read_value_id(currentNode, attr));
    mLastAttribute = attr;
  }
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::data_encoding(ua::QualifiedName encoding)
{
  mutate_last().data_encoding() = std::move(encoding);
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::index_range(ua::String range)
{
  mutate_last().index_range() = std::move(range);
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::timestamps(ua::TimestampsToReturn timestamps)
{
  mRequest.timestamps_to_return() = timestamps;
  return *this;
}

ReadRequestBuilder& ReadRequestBuilder::max_age(double maxAgeMs)
{
  mRequest.max_age() = maxAgeMs;
  return *this;
}

ua::ReadRequest ReadRequestBuilder::build()
{
  flush_pending();
  return std::move(mRequest);
}

ReadRequestBuilder::operator ua::ReadRequest()
{
  return build();
}

void ReadRequestBuilder::flush_pending()
{
  if (mHasPending)
  {
    mRequest.nodes_to_read().push_back(std::move(mPending));
    mPending = ua::ReadValueId{};
    mHasPending = false;
  }
}

ua::ReadValueId& ReadRequestBuilder::mutate_last()
{
  if (mHasPending)
  {
    return mPending;
  }
  // Calling .data_encoding()/.index_range() with no entry to modify is a programming
  // error in the test (no .read() before the modifier). Throw rather than return a
  // dangling reference; GoogleTest catches the exception and reports the test as failed.
  if (mRequest.nodes_to_read().empty())
  {
    throw std::logic_error("ReadRequestBuilder modifier called with no entry to modify; use .read() first");
  }
  return mRequest.nodes_to_read()[mRequest.nodes_to_read().size() - 1];
}

// ---------------------------------------------------------------------------
// WriteRequestBuilder
// ---------------------------------------------------------------------------

WriteRequestBuilder& WriteRequestBuilder::write(
  const ua::NodeId& node, ua::Variant value, ua::AttributeId attr)
{
  mRequest.nodes_to_write().push_back(make_write_value(node, attr, ua::DataValue{std::move(value)}));
  return *this;
}

WriteRequestBuilder& WriteRequestBuilder::write(
  const ua::NodeId& node, ua::DataValue value, ua::AttributeId attr)
{
  mRequest.nodes_to_write().push_back(make_write_value(node, attr, std::move(value)));
  return *this;
}

WriteRequestBuilder& WriteRequestBuilder::index_range(ua::String range)
{
  if (mRequest.nodes_to_write().empty())
  {
    throw std::logic_error("WriteRequestBuilder::index_range called with no entry; use .write() first");
  }
  auto& last = mRequest.nodes_to_write()[mRequest.nodes_to_write().size() - 1];
  last.index_range() = std::move(range);
  return *this;
}

ua::WriteRequest WriteRequestBuilder::build()
{
  return std::move(mRequest);
}

WriteRequestBuilder::operator ua::WriteRequest()
{
  return build();
}

// ---------------------------------------------------------------------------
// write_value
// ---------------------------------------------------------------------------

void write_value_async(ua::client::Session& session, const ua::NodeId& node, ua::DataValue value)
{
  ua::WriteRequest req;
  req.nodes_to_write().push_back(make_write_value(node, ua::AttributeId::Value, std::move(value)));
  auto resp = session.attributes().write_sync(std::move(req));

  // write_value is a precondition helper - callers downstream rely on the write
  // having succeeded. Throw on failure so the test aborts cleanly with a clear
  // diagnostic, rather than continuing into a misleading follow-on assertion.
  // GoogleTest catches the exception and marks the test failed.
  const auto serviceResult = resp.response_header().service_result();
  if (!serviceResult.is_good())
  {
    std::ostringstream oss;
    oss << "write_value: service_result = 0x" << std::hex << serviceResult.as_uint32();
    throw std::runtime_error(oss.str());
  }
  if (resp.results().size() != 1u)
  {
    std::ostringstream oss;
    oss << "write_value: results.size() = " << resp.results().size();
    throw std::runtime_error(oss.str());
  }
  if (!resp.results()[0].is_good())
  {
    std::ostringstream oss;
    oss << "write_value: result status = 0x" << std::hex << resp.results()[0].as_uint32();
    throw std::runtime_error(oss.str());
  }
}

void write_value_async(ua::client::Session& session, const ua::NodeId& node, ua::Variant value)
{
  write_value_async(session, node, ua::DataValue{std::move(value)});
}

// ---------------------------------------------------------------------------
// Browse
// ---------------------------------------------------------------------------

namespace
{

ua::BrowseDescription make_default_browse_desc(const ua::NodeId& node)
{
  ua::BrowseDescription desc;
  desc.node_id() = node;
  desc.browse_direction() = ua::BrowseDirection::Forward;
  desc.reference_type_id() = ua::NodeId{};  // {} = match all
  desc.include_subtypes() = true;
  desc.node_class_mask() = 0u;  // 0 = all classes
  desc.result_mask() = static_cast<uint32_t>(ua::BrowseResultMask::All);
  return desc;
}

}  // namespace

ua::BrowseRequest browse(const ua::NodeId& node)
{
  ua::BrowseRequest req;
  req.nodes_to_browse().push_back(make_default_browse_desc(node));
  return req;
}

ua::BrowseNextRequest browse_next(ua::ContinuationPoint cp, bool release)
{
  ua::BrowseNextRequest req;
  req.release_continuation_points() = release;
  req.continuation_points().push_back(std::move(cp));
  return req;
}

ua::BrowseNextRequest browse_next(std::initializer_list<ua::ContinuationPoint> cps, bool release)
{
  ua::BrowseNextRequest req;
  req.release_continuation_points() = release;
  for (const auto& cp : cps)
  {
    req.continuation_points().push_back(cp);
  }
  return req;
}

BrowseRequestBuilder& BrowseRequestBuilder::browse(const ua::NodeId& node)
{
  mRequest.nodes_to_browse().push_back(make_default_browse_desc(node));
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::direction(ua::BrowseDirection dir)
{
  mutate_last().browse_direction() = dir;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::reference_type(const ua::NodeId& refType)
{
  mutate_last().reference_type_id() = refType;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::include_subtypes(bool yes)
{
  mutate_last().include_subtypes() = yes;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::node_class_mask(uint32_t mask)
{
  mutate_last().node_class_mask() = mask;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::result_mask(uint32_t mask)
{
  mutate_last().result_mask() = mask;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::max_references_per_node(uint32_t n)
{
  mRequest.requested_max_references_per_node() = n;
  return *this;
}

BrowseRequestBuilder& BrowseRequestBuilder::view(const ua::NodeId& viewId)
{
  mRequest.view().view_id() = viewId;
  return *this;
}

ua::BrowseRequest BrowseRequestBuilder::build()
{
  return std::move(mRequest);
}

BrowseRequestBuilder::operator ua::BrowseRequest()
{
  return build();
}

ua::BrowseDescription& BrowseRequestBuilder::mutate_last()
{
  if (mRequest.nodes_to_browse().empty())
  {
    throw std::logic_error(
      "BrowseRequestBuilder modifier called with no entry to modify; use .browse() first");
  }
  return mRequest.nodes_to_browse()[mRequest.nodes_to_browse().size() - 1];
}

// ---------------------------------------------------------------------------
// RegisterNodes / UnregisterNodes
// ---------------------------------------------------------------------------

ua::RegisterNodesRequest register_nodes(const ua::NodeId& node)
{
  ua::RegisterNodesRequest req;
  req.nodes_to_register().push_back(node);
  return req;
}

ua::RegisterNodesRequest register_nodes(std::initializer_list<ua::NodeId> nodes)
{
  ua::RegisterNodesRequest req;
  for (const auto& node : nodes)
  {
    req.nodes_to_register().push_back(node);
  }
  return req;
}

ua::UnregisterNodesRequest unregister_nodes(const ua::NodeId& node)
{
  ua::UnregisterNodesRequest req;
  req.nodes_to_unregister().push_back(node);
  return req;
}

ua::UnregisterNodesRequest unregister_nodes(std::initializer_list<ua::NodeId> nodes)
{
  ua::UnregisterNodesRequest req;
  for (const auto& node : nodes)
  {
    req.nodes_to_unregister().push_back(node);
  }
  return req;
}

// ---------------------------------------------------------------------------
// TranslateBrowsePathsToNodeIds
// ---------------------------------------------------------------------------

namespace
{

ua::RelativePathElement make_default_step(const ua::QualifiedName& targetName)
{
  ua::RelativePathElement elem;
  elem.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences};
  elem.is_inverse() = false;
  elem.include_subtypes() = true;
  elem.target_name() = targetName;
  return elem;
}

}  // namespace

ua::TranslateBrowsePathsToNodeIdsRequest translate_path(
  const ua::NodeId& startNode, const ua::QualifiedName& targetName)
{
  ua::BrowsePath bp;
  bp.starting_node() = startNode;
  bp.relative_path().elements().push_back(make_default_step(targetName));
  ua::TranslateBrowsePathsToNodeIdsRequest req;
  req.browse_paths().push_back(std::move(bp));
  return req;
}

TranslateBrowsePathsBuilder& TranslateBrowsePathsBuilder::path(const ua::NodeId& startNode)
{
  ua::BrowsePath bp;
  bp.starting_node() = startNode;
  mRequest.browse_paths().push_back(std::move(bp));
  return *this;
}

TranslateBrowsePathsBuilder& TranslateBrowsePathsBuilder::step(const ua::QualifiedName& targetName)
{
  mutate_last_path().relative_path().elements().push_back(make_default_step(targetName));
  return *this;
}

TranslateBrowsePathsBuilder& TranslateBrowsePathsBuilder::reference_type(const ua::NodeId& refTypeId)
{
  mutate_last_step().reference_type_id() = refTypeId;
  return *this;
}

TranslateBrowsePathsBuilder& TranslateBrowsePathsBuilder::is_inverse(bool yes)
{
  mutate_last_step().is_inverse() = yes;
  return *this;
}

TranslateBrowsePathsBuilder& TranslateBrowsePathsBuilder::include_subtypes(bool yes)
{
  mutate_last_step().include_subtypes() = yes;
  return *this;
}

ua::TranslateBrowsePathsToNodeIdsRequest TranslateBrowsePathsBuilder::build()
{
  return std::move(mRequest);
}

TranslateBrowsePathsBuilder::operator ua::TranslateBrowsePathsToNodeIdsRequest()
{
  return build();
}

ua::BrowsePath& TranslateBrowsePathsBuilder::mutate_last_path()
{
  if (mRequest.browse_paths().empty())
  {
    throw std::logic_error(
      "TranslateBrowsePathsBuilder::step()/modifier called with no path; use .path() first");
  }
  return mRequest.browse_paths()[mRequest.browse_paths().size() - 1];
}

ua::RelativePathElement& TranslateBrowsePathsBuilder::mutate_last_step()
{
  auto& lastPath = mutate_last_path();
  if (lastPath.relative_path().elements().empty())
  {
    throw std::logic_error("TranslateBrowsePathsBuilder modifier called with no step; use .step() first");
  }
  return lastPath.relative_path().elements()[lastPath.relative_path().elements().size() - 1];
}

// ---------------------------------------------------------------------------
// Call
// ---------------------------------------------------------------------------

namespace
{

ua::CallMethodRequest make_call_method_request(const ua::NodeId& objectId, const ua::NodeId& methodId)
{
  ua::CallMethodRequest req;
  req.object_id() = objectId;
  req.method_id() = methodId;
  return req;
}

}  // namespace

ua::CallRequest call_method(const ua::NodeId& objectId, const ua::NodeId& methodId)
{
  ua::CallRequest req;
  req.methods_to_call().push_back(make_call_method_request(objectId, methodId));
  return req;
}

ua::CallRequest call_method(
  const ua::NodeId& objectId, const ua::NodeId& methodId, std::initializer_list<ua::Variant> args)
{
  ua::CallRequest req;
  auto entry = make_call_method_request(objectId, methodId);
  for (const auto& arg : args)
  {
    entry.input_arguments().push_back(arg);
  }
  req.methods_to_call().push_back(std::move(entry));
  return req;
}

CallRequestBuilder& CallRequestBuilder::call(const ua::NodeId& objectId, const ua::NodeId& methodId)
{
  mRequest.methods_to_call().push_back(make_call_method_request(objectId, methodId));
  return *this;
}

CallRequestBuilder& CallRequestBuilder::call(
  const ua::NodeId& objectId, const ua::NodeId& methodId, std::initializer_list<ua::Variant> args)
{
  auto entry = make_call_method_request(objectId, methodId);
  for (const auto& arg : args)
  {
    entry.input_arguments().push_back(arg);
  }
  mRequest.methods_to_call().push_back(std::move(entry));
  return *this;
}

CallRequestBuilder& CallRequestBuilder::argument(ua::Variant value)
{
  mutate_last().input_arguments().push_back(std::move(value));
  return *this;
}

ua::CallRequest CallRequestBuilder::build()
{
  return std::move(mRequest);
}

CallRequestBuilder::operator ua::CallRequest()
{
  return build();
}

ua::CallMethodRequest& CallRequestBuilder::mutate_last()
{
  if (mRequest.methods_to_call().empty())
  {
    throw std::logic_error("CallRequestBuilder::argument() called with no call; use .call() first");
  }
  return mRequest.methods_to_call()[mRequest.methods_to_call().size() - 1];
}

// ---------------------------------------------------------------------------
// AddNodesBuilder
// ---------------------------------------------------------------------------

AddNodesBuilder& AddNodesBuilder::add_node(
  const ua::NodeId& parentNodeId, const ua::QualifiedName& browseName, ua::NodeClass nodeClass)
{
  ua::AddNodesItem item;
  item.parent_node_id() = ua::ExpandedNodeId{parentNodeId};
  item.browse_name() = browseName;
  item.node_class() = nodeClass;
  mRequest.nodes_to_add().push_back(std::move(item));
  return *this;
}

AddNodesBuilder& AddNodesBuilder::reference_type(const ua::NodeId& refTypeId)
{
  mutate_last().reference_type_id() = refTypeId;
  return *this;
}

AddNodesBuilder& AddNodesBuilder::requested_node_id(const ua::NodeId& id)
{
  mutate_last().requested_new_node_id() = ua::ExpandedNodeId{id};
  return *this;
}

AddNodesBuilder& AddNodesBuilder::requested_node_id(const ua::ExpandedNodeId& id)
{
  mutate_last().requested_new_node_id() = id;
  return *this;
}

AddNodesBuilder& AddNodesBuilder::type_definition(const ua::NodeId& td)
{
  mutate_last().type_definition() = ua::ExpandedNodeId{td};
  return *this;
}

AddNodesBuilder& AddNodesBuilder::type_definition(const ua::ExpandedNodeId& td)
{
  mutate_last().type_definition() = td;
  return *this;
}

ua::AddNodesRequest AddNodesBuilder::build()
{
  return std::move(mRequest);
}

AddNodesBuilder::operator ua::AddNodesRequest()
{
  return build();
}

ua::AddNodesItem& AddNodesBuilder::mutate_last()
{
  if (mRequest.nodes_to_add().empty())
  {
    throw std::logic_error("AddNodesBuilder modifier called with no entry; use .add_node() first");
  }
  return mRequest.nodes_to_add()[mRequest.nodes_to_add().size() - 1];
}

// ---------------------------------------------------------------------------
// DeleteNodes
// ---------------------------------------------------------------------------

namespace
{

ua::DeleteNodesItem make_delete_nodes_item(const ua::NodeId& id, bool deleteTargetReferences)
{
  ua::DeleteNodesItem item;
  item.node_id() = id;
  item.delete_target_references() = deleteTargetReferences;
  return item;
}

}  // namespace

ua::DeleteNodesRequest delete_node(const ua::NodeId& id, bool deleteTargetReferences)
{
  ua::DeleteNodesRequest req;
  req.nodes_to_delete().push_back(make_delete_nodes_item(id, deleteTargetReferences));
  return req;
}

ua::DeleteNodesRequest delete_nodes(std::initializer_list<ua::NodeId> ids, bool deleteTargetReferences)
{
  ua::DeleteNodesRequest req;
  for (const auto& id : ids)
  {
    req.nodes_to_delete().push_back(make_delete_nodes_item(id, deleteTargetReferences));
  }
  return req;
}

DeleteNodesBuilder& DeleteNodesBuilder::delete_node(const ua::NodeId& id, bool deleteTargetReferences)
{
  mRequest.nodes_to_delete().push_back(make_delete_nodes_item(id, deleteTargetReferences));
  return *this;
}

ua::DeleteNodesRequest DeleteNodesBuilder::build()
{
  return std::move(mRequest);
}

DeleteNodesBuilder::operator ua::DeleteNodesRequest()
{
  return build();
}

// ---------------------------------------------------------------------------
// AddReferencesBuilder
// ---------------------------------------------------------------------------

AddReferencesBuilder& AddReferencesBuilder::add_reference_async(
  const ua::NodeId& source, const ua::NodeId& referenceType, const ua::NodeId& target)
{
  ua::AddReferencesItem item;
  item.source_node_id() = source;
  item.reference_type_id() = referenceType;
  item.is_forward() = true;
  item.target_node_id() = ua::ExpandedNodeId{target};
  item.target_node_class() = ua::NodeClass::Object;
  mRequest.references_to_add().push_back(std::move(item));
  return *this;
}

AddReferencesBuilder& AddReferencesBuilder::is_forward(bool yes)
{
  mutate_last().is_forward() = yes;
  return *this;
}

AddReferencesBuilder& AddReferencesBuilder::target_node_class(ua::NodeClass nc)
{
  mutate_last().target_node_class() = nc;
  return *this;
}

AddReferencesBuilder& AddReferencesBuilder::target_server_uri(ua::String uri)
{
  mutate_last().target_server_uri() = std::move(uri);
  return *this;
}

ua::AddReferencesRequest AddReferencesBuilder::build()
{
  return std::move(mRequest);
}

AddReferencesBuilder::operator ua::AddReferencesRequest()
{
  return build();
}

ua::AddReferencesItem& AddReferencesBuilder::mutate_last()
{
  if (mRequest.references_to_add().empty())
  {
    throw std::logic_error(
      "AddReferencesBuilder modifier called with no entry; use .add_reference_async() first");
  }
  return mRequest.references_to_add()[mRequest.references_to_add().size() - 1];
}

// ---------------------------------------------------------------------------
// DeleteReferencesBuilder
// ---------------------------------------------------------------------------

DeleteReferencesBuilder& DeleteReferencesBuilder::delete_reference(
  const ua::NodeId& source, const ua::NodeId& referenceType, const ua::NodeId& target)
{
  ua::DeleteReferencesItem item;
  item.source_node_id() = source;
  item.reference_type_id() = referenceType;
  item.is_forward() = true;
  item.target_node_id() = ua::ExpandedNodeId{target};
  item.delete_bidirectional() = true;
  mRequest.references_to_delete().push_back(std::move(item));
  return *this;
}

DeleteReferencesBuilder& DeleteReferencesBuilder::is_forward(bool yes)
{
  mutate_last().is_forward() = yes;
  return *this;
}

DeleteReferencesBuilder& DeleteReferencesBuilder::delete_bidirectional(bool yes)
{
  mutate_last().delete_bidirectional() = yes;
  return *this;
}

ua::DeleteReferencesRequest DeleteReferencesBuilder::build()
{
  return std::move(mRequest);
}

DeleteReferencesBuilder::operator ua::DeleteReferencesRequest()
{
  return build();
}

ua::DeleteReferencesItem& DeleteReferencesBuilder::mutate_last()
{
  if (mRequest.references_to_delete().empty())
  {
    throw std::logic_error(
      "DeleteReferencesBuilder modifier called with no entry; use .delete_reference() first");
  }
  return mRequest.references_to_delete()[mRequest.references_to_delete().size() - 1];
}

// ---------------------------------------------------------------------------
// HistoryRead - raw/modified
// ---------------------------------------------------------------------------

namespace
{

ua::HistoryReadValueId make_history_read_value_id(
  const ua::NodeId& node, ua::ContinuationPoint cp = ua::ContinuationPoint{})
{
  ua::HistoryReadValueId rv;
  rv.node_id() = node;
  rv.continuation_point() = std::move(cp);
  return rv;
}

}  // namespace

ua::HistoryReadRequest history_read_raw(
  const ua::NodeId& node, const ua::DateTime& start, const ua::DateTime& end, uint32_t numValuesPerNode)
{
  auto details = std::make_unique<ua::ReadRawModifiedDetails>();
  details->is_read_modified() = false;
  details->start_time() = start;
  details->end_time() = end;
  details->num_values_per_node() = numValuesPerNode;
  details->return_bounds() = false;

  ua::HistoryReadRequest req;
  req.history_read_details() = std::move(details);
  req.timestamps_to_return() = ua::TimestampsToReturn::Both;
  req.release_continuation_points() = false;
  req.nodes_to_read().push_back(make_history_read_value_id(node));
  return req;
}

HistoryReadRawBuilder::HistoryReadRawBuilder(
  const ua::DateTime& start, const ua::DateTime& end, uint32_t numValuesPerNode)
  : mDetails(std::make_unique<ua::ReadRawModifiedDetails>())
{
  mDetails->is_read_modified() = false;
  mDetails->start_time() = start;
  mDetails->end_time() = end;
  mDetails->num_values_per_node() = numValuesPerNode;
  mDetails->return_bounds() = false;
  mRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
  mRequest.release_continuation_points() = false;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::is_read_modified(bool yes)
{
  mDetails->is_read_modified() = yes;
  return *this;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::return_bounds(bool yes)
{
  mDetails->return_bounds() = yes;
  return *this;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::timestamps(ua::TimestampsToReturn ts)
{
  mRequest.timestamps_to_return() = ts;
  return *this;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::release_continuation_points(bool yes)
{
  mRequest.release_continuation_points() = yes;
  return *this;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::read(const ua::NodeId& node)
{
  mRequest.nodes_to_read().push_back(make_history_read_value_id(node));
  return *this;
}

HistoryReadRawBuilder& HistoryReadRawBuilder::read(const ua::NodeId& node, ua::ContinuationPoint cp)
{
  mRequest.nodes_to_read().push_back(make_history_read_value_id(node, std::move(cp)));
  return *this;
}

ua::HistoryReadRequest HistoryReadRawBuilder::build()
{
  mRequest.history_read_details() = std::move(mDetails);
  return std::move(mRequest);
}

HistoryReadRawBuilder::operator ua::HistoryReadRequest()
{
  return build();
}

}  // namespace ua::test_helpers
