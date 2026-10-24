// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the pure FileType instance-method resolution helpers (CL-FILE-001) - the
// TranslateBrowsePaths request builder and its response interpreter, extracted from FileTransferClient so
// every branch (all-resolved / Open-missing / partial / wrong-count / remote-target / service-bad) is
// unit-testable without a live server. See design: a Call's methodId must be a Method component of the
// objectId (OPC 10000-4 section 5.11.2), never the abstract FileType method declaration.

#include "ua_file_method_resolution.h"

#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include <gtest/gtest.h>

using namespace ua;
using ua::client::detail::build_file_method_browse_paths;
using ua::client::detail::FileMethodNodes;
using ua::client::detail::interpret_file_method_resolution;

namespace
{

// A Good BrowsePathResult resolving to one local instance NodeId.
BrowsePathResult good_target(std::uint32_t identifier)
{
  BrowsePathResult result;
  result.status_code() = StatusCode{Status::Good};
  BrowsePathTarget target;
  target.target_id() = ExpandedNodeId{NodeId{identifier}};
  result.targets().push_back(std::move(target));
  return result;
}

// A Bad (unresolved) BrowsePathResult - the single hop had no match.
BrowsePathResult no_match()
{
  BrowsePathResult result;
  result.status_code() = StatusCode{Status::BadNoMatch};
  return result;
}

// The six well-known instance method NodeIds used across the resolve tests.
constexpr std::uint32_t open = 5001;
constexpr std::uint32_t read = 5002;
constexpr std::uint32_t write = 5003;
constexpr std::uint32_t close = 5004;
constexpr std::uint32_t getPos = 5005;
constexpr std::uint32_t setPos = 5006;

TranslateBrowsePathsToNodeIdsResponse all_resolved()
{
  TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(good_target(open));
  response.results().push_back(good_target(read));
  response.results().push_back(good_target(write));
  response.results().push_back(good_target(close));
  response.results().push_back(good_target(getPos));
  response.results().push_back(good_target(setPos));
  response.results().push_back(no_match());
  response.results().push_back(good_target(5008));
  return response;
}

// ---- build_file_method_browse_paths ----

// @verifies CL-FILE-002
// The request emits the six method paths plus the optional per-file MaxByteStringLength Property path.
// @relation(CL-FILE-002, scope=function)
TEST(FileMethodResolution, BuildEmitsMethodsAndMaxByteStringLengthPropertyPath)
{
  const NodeId fileNode{4242};
  const auto request = build_file_method_browse_paths(fileNode);

  ASSERT_EQ(request.browse_paths().size(), 8U);
  const char* const expected[] = {"Open", "Read", "Write", "Close", "GetPosition", "SetPosition"};
  for (std::size_t i = 0; i < 6; ++i)
  {
    const auto& browsePath = request.browse_paths()[i];
    EXPECT_EQ(browsePath.starting_node(), fileNode);
    ASSERT_EQ(browsePath.relative_path().elements().size(), 1U);
    const auto& element = browsePath.relative_path().elements()[0];
    EXPECT_EQ(element.reference_type_id(), NodeId{ReferenceTypeId::HasComponent});
    EXPECT_FALSE(element.is_inverse());
    EXPECT_EQ(element.target_name().name(), expected[i]);
    EXPECT_EQ(element.target_name().namespace_index(), 0U);
  }
  const auto& propertyPath = request.browse_paths()[6];
  EXPECT_EQ(propertyPath.starting_node(), fileNode);
  ASSERT_EQ(propertyPath.relative_path().elements().size(), 1U);
  const auto& propertyElement = propertyPath.relative_path().elements()[0];
  EXPECT_EQ(propertyElement.reference_type_id(), NodeId{ReferenceTypeId::HasProperty});
  EXPECT_FALSE(propertyElement.is_inverse());
  EXPECT_EQ(propertyElement.target_name(), (QualifiedName{0, "MaxByteStringLength"}));
  const auto& writableElement = request.browse_paths()[7].relative_path().elements()[0];
  EXPECT_EQ(writableElement.reference_type_id(), NodeId{ReferenceTypeId::HasProperty});
  EXPECT_EQ(writableElement.target_name(), (QualifiedName{0, "UserWritable"}));
}

// ---- interpret_file_method_resolution ----

// A service-level bad Result propagates verbatim (code preserved), never a partial FileMethodNodes.
TEST(FileMethodResolution, InterpretPropagatesServiceBad)
{
  const auto result = interpret_file_method_resolution(
    Result<TranslateBrowsePathsToNodeIdsResponse>{StatusCode{Status::BadServiceUnsupported}});
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadServiceUnsupported);
}

// A response whose result count does not match the six requested paths cannot be mapped ->
// BadUnexpectedError.
TEST(FileMethodResolution, InterpretRejectsWrongResultCount)
{
  TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(good_target(open));  // only one result, not six
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadUnexpectedError);
}

// All six methods resolve to their instance nodes.
TEST(FileMethodResolution, InterpretResolvesAllSixMethods)
{
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{all_resolved()});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().open, NodeId{open});
  EXPECT_EQ(result.value().read, NodeId{read});
  EXPECT_EQ(result.value().write, NodeId{write});
  EXPECT_EQ(result.value().close, NodeId{close});
  EXPECT_EQ(result.value().getPosition, NodeId{getPos});
  EXPECT_EQ(result.value().setPosition, NodeId{setPos});
}

// The Open method is the precondition: if its path did not resolve, the object is not a usable FileType.
TEST(FileMethodResolution, InterpretRequiresOpenElseMethodInvalid)
{
  TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(no_match());  // Open unresolved
  response.results().push_back(good_target(read));
  response.results().push_back(good_target(write));
  response.results().push_back(good_target(close));
  response.results().push_back(good_target(getPos));
  response.results().push_back(good_target(setPos));
  response.results().push_back(no_match());
  response.results().push_back(good_target(5008));
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadMethodInvalid);
}

// A non-Open method that did not resolve is left null (a minimal / read-only File may omit Write); the rest
// still resolve and the result is Good.
TEST(FileMethodResolution, InterpretLeavesUnresolvedNonOpenMethodNull)
{
  TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(good_target(open));
  response.results().push_back(good_target(read));
  response.results().push_back(no_match());  // Write absent (read-only File)
  response.results().push_back(good_target(close));
  response.results().push_back(good_target(getPos));
  response.results().push_back(good_target(setPos));
  response.results().push_back(no_match());
  response.results().push_back(good_target(5008));
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().open, NodeId{open});
  EXPECT_TRUE(result.value().write.is_null()) << "an unresolved Write must be null, not the abstract id";
  EXPECT_EQ(result.value().read, NodeId{read});
  EXPECT_EQ(result.value().close, NodeId{close});
}

// A namespace-URI-addressed Open target is not usable: the URI supersedes the wrapped NodeId's numeric
// namespace, so node_id() would carry a wrong index. It is treated as unresolved -> MethodInvalid.
// (is_local() keys only on the server index and would NOT catch this - the explicit namespace_uri guard
// does.)
TEST(FileMethodResolution, InterpretRejectsNamespaceUriOpenTarget)
{
  TranslateBrowsePathsToNodeIdsResponse response;
  BrowsePathResult uriOpen;
  uriOpen.status_code() = StatusCode{Status::Good};
  BrowsePathTarget target;
  target.target_id() = ExpandedNodeId{NodeId{open}, "urn:some:other:namespace"};  // URI form, server index 0
  uriOpen.targets().push_back(std::move(target));
  response.results().push_back(std::move(uriOpen));
  for (std::uint32_t id : {read, write, close, getPos, setPos})
  {
    response.results().push_back(good_target(id));
  }
  response.results().push_back(no_match());
  response.results().push_back(good_target(5008));
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  EXPECT_TRUE(result.is_bad())
    << "a namespace-URI-addressed Open target must not be accepted as a local Call";
  EXPECT_EQ(result.status_code().as_status(), Status::BadMethodInvalid);
}

// A remote (non-local) Open target is not usable for a local Call -> treated as unresolved -> MethodInvalid.
TEST(FileMethodResolution, InterpretRejectsRemoteOpenTarget)
{
  TranslateBrowsePathsToNodeIdsResponse response;
  BrowsePathResult remoteOpen;
  remoteOpen.status_code() = StatusCode{Status::Good};
  BrowsePathTarget target;
  ExpandedNodeId remote{NodeId{open}};
  remote.server_index() = 7;  // a target on another server - not locally callable
  target.target_id() = std::move(remote);
  remoteOpen.targets().push_back(std::move(target));
  response.results().push_back(std::move(remoteOpen));
  for (std::uint32_t id : {read, write, close, getPos, setPos})
  {
    response.results().push_back(good_target(id));
  }
  response.results().push_back(no_match());
  response.results().push_back(good_target(5008));
  const auto result =
    interpret_file_method_resolution(Result<TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadMethodInvalid);
}

}  // namespace
