// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_METHOD_RESOLUTION_H
#define UA_FILE_METHOD_RESOLUTION_H

/// @file
/// @brief Resolves a FileType Object's INSTANCE method nodes (Open/Read/Write/Close/GetPosition/
///        SetPosition) via TranslateBrowsePathsToNodeIds, so `FileTransferClient` Calls the method
///        component of the file object (OPC 10000-4 section 5.11.2) rather than the abstract FileType method
///        declaration  -  which a conformant server rejects (Bad_MethodInvalid). Pure + unit-testable.
/// @ingroup client

#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

namespace ua::client::detail
{

/// The resolved INSTANCE method nodes of one FileType Object. A null NodeId means the server did not expose
/// that method as a browsable component (a minimal / read-only File legitimately may omit Write); the
/// corresponding `FileHandle` op then fails locally with `Bad_MethodInvalid` rather than issuing a wrong
/// Call. `open` is always non-null in a successfully-interpreted result (it is the resolution precondition).
struct FileMethodNodes
{
  ua::NodeId open;
  ua::NodeId read;
  ua::NodeId write;
  ua::NodeId close;
  ua::NodeId getPosition;
  ua::NodeId setPosition;
  ua::NodeId maxByteStringLength;
  ua::NodeId userWritable;
};

/// Builds the `TranslateBrowsePathsToNodeIds` request that resolves @p fileNode's six FileType instance
/// method nodes and its optional MaxByteStringLength Property. Each browse path is a single forward hop,
/// emitted in the fixed order Open, Read, Write, Close, GetPosition, SetPosition (HasComponent), then
/// MaxByteStringLength and UserWritable (HasProperty).
[[nodiscard]] ua::TranslateBrowsePathsToNodeIdsRequest build_file_method_browse_paths(
  const ua::NodeId& fileNode);

/// Interprets the response of a @ref build_file_method_browse_paths request into @ref FileMethodNodes.
///
/// - A service-level bad Result propagates verbatim (code + ErrorDetail).
/// - The response must carry exactly eight results (one per requested path, in order)  -  otherwise a
///   source-tagged `Bad_UnexpectedError` (a non-conformant TBP response cannot be mapped).
/// - Each result contributes its method node iff it is Good with at least one fully-resolved LOCAL target
///   (server index 0, no namespace-URI form, non-null NodeId); otherwise that method is left null. A
///   single-hop path cannot partially match (the hop either resolves or the server returns Bad_NoMatch),
///   so a Good status implies full resolution.
/// - The **Open** node (result index 0) is the precondition: if it does not resolve, the object is not a
///   usable FileType and the whole resolution fails with a source-tagged `Bad_MethodInvalid`.
[[nodiscard]] ua::Result<FileMethodNodes> interpret_file_method_resolution(
  ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> response);

}  // namespace ua::client::detail

#endif  // UA_FILE_METHOD_RESOLUTION_H
