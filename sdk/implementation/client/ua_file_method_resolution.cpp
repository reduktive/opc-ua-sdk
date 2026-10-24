// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_method_resolution.h"

#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_client_answer_status.h"
#include "ua_error_detail.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_status.h"

#include <array>
#include <string>
#include <string_view>

namespace ua::client::detail
{

namespace
{
constexpr std::string_view resolveSource = "client.tier1.file.method_resolution";

// The six FileType method BrowseNames, in the fixed order the request emits and the response is consumed.
constexpr std::array<std::string_view, 6> methodNames{
  "Open", "Read", "Write", "Close", "GetPosition", "SetPosition"};

// Extracts the single fully-resolved LOCAL target NodeId of one browse-path result, or a null NodeId if the
// result did not resolve (bad status, no target, a remote / namespace-URI target, or a null node). A
// single-element path cannot partially match, so a Good status with a local target is a full resolution.
ua::NodeId resolved_local_target(const ua::BrowsePathResult& result)
{
  if (result.status_code().is_bad() || result.targets().empty())
  {
    return ua::NodeId{};
  }
  const ua::ExpandedNodeId& target = result.targets()[0].target_id();
  // Accept only a fully-resolved, index-based LOCAL target. Reject:
  //  - a REMOTE target (server index != 0)  -  not callable on this Session;
  //  - a NAMESPACE-URI-addressed target  -  its URI supersedes the wrapped NodeId's numeric namespace index
  //    (ExpandedNodeId semantics), so `node_id()` would carry a wrong / placeholder index; `is_local()` keys
  //    only on the server index and does NOT catch this, so it is checked explicitly here;
  //  - a null wrapped NodeId.
  // A method component the client can Call is addressed by numeric index on this server. A single-hop path
  // cannot partially match, so a Good status with a local index-based target is a full resolution  -  the
  // TBP `remaining_path_index` is not additionally gated (a partial value cannot occur for one hop).
  if (!target.is_local() || !target.namespace_uri().empty() || target.node_id().is_null())
  {
    return ua::NodeId{};
  }
  return target.node_id();
}
}  // namespace

ua::TranslateBrowsePathsToNodeIdsRequest build_file_method_browse_paths(const ua::NodeId& fileNode)
{
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  for (const std::string_view methodName : methodNames)
  {
    ua::RelativePathElement element;
    element.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasComponent};
    element.is_inverse() = false;
    element.include_subtypes() = false;
    element.target_name() = ua::QualifiedName{0, methodName};

    ua::BrowsePath browsePath;
    browsePath.starting_node() = fileNode;
    browsePath.relative_path().elements().push_back(std::move(element));
    request.browse_paths().push_back(std::move(browsePath));
  }
  for (const std::string_view propertyName : {"MaxByteStringLength", "UserWritable"})
  {
    ua::RelativePathElement propertyElement;
    propertyElement.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasProperty};
    propertyElement.is_inverse() = false;
    propertyElement.include_subtypes() = false;
    propertyElement.target_name() = ua::QualifiedName{0, propertyName};
    ua::BrowsePath propertyPath;
    propertyPath.starting_node() = fileNode;
    propertyPath.relative_path().elements().push_back(std::move(propertyElement));
    request.browse_paths().push_back(std::move(propertyPath));
  }
  return request;
}

ua::Result<FileMethodNodes> interpret_file_method_resolution(
  ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> response)
{
  // The SDK calls the Methods this lookup finds, so only a Good answer is used: an Uncertain answer, to the
  // service or to any path, is refused (ReferencesAnswerUncertain), as a Bad service answer fails it.
  if (!response.is_good())
  {
    // Service-level failure (transport / TBP unsupported / auth): propagate the rich StatusCode verbatim.
    return ua::Result<FileMethodNodes>{
      answer_refused(response.status_code(), "ReferencesAnswerUncertain", resolveSource)};
  }
  const ua::StatusCode serviceResult = response.value().response_header().service_result();
  if (!serviceResult.is_good())
  {
    return ua::Result<FileMethodNodes>{
      answer_refused(serviceResult, "ReferencesAnswerUncertain", resolveSource)};
  }
  const ua::Array<ua::BrowsePathResult>& results = response.value().results();
  for (const auto& result : results)
  {
    if (result.status_code().is_uncertain())
    {
      return ua::Result<FileMethodNodes>{
        uncertain_answer_refused(result.status_code(), "ReferencesAnswerUncertain", resolveSource)};
    }
  }
  if (results.size() != methodNames.size() + 2)
  {
    return ua::Result<FileMethodNodes>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("FileMethodResolutionResultCount",
        "TranslateBrowsePaths returned a result count that does not match the requested FileType method "
        "and Property paths",
        std::string{resolveSource})};
  }
  FileMethodNodes methods;
  methods.open = resolved_local_target(results[0]);
  methods.read = resolved_local_target(results[1]);
  methods.write = resolved_local_target(results[2]);
  methods.close = resolved_local_target(results[3]);
  methods.getPosition = resolved_local_target(results[4]);
  methods.setPosition = resolved_local_target(results[5]);
  methods.maxByteStringLength = resolved_local_target(results[6]);
  methods.userWritable = resolved_local_target(results[7]);
  if (methods.open.is_null())
  {
    // No instance Open method  to  the target is not a usable FileType Object (or does not expose Open as a
    // browsable component). Fail rather than fall back to the abstract FileType.Open, which a conformant
    // server rejects (OPC 10000-4 section 5.11.2).
    return ua::Result<FileMethodNodes>{ua::Status::BadMethodInvalid,
      ua::make_error_detail("FileMethodResolutionNoOpen",
        "the file object does not expose an instance Open method (its 'Open' HasComponent path did not "
        "resolve) - it is not a usable FileType Object",
        std::string{resolveSource})};
  }
  return ua::Result<FileMethodNodes>{std::move(methods)};
}

}  // namespace ua::client::detail
