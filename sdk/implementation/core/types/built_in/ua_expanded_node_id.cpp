// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <charconv>
#include <exception>
#include "ua_to_result.h"
#include "ua_expanded_node_id.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "fmt/format.h"

namespace ua
{

ExpandedNodeId::ExpandedNodeId(NodeId nodeId) : mNodeId(nodeId)
{}

ExpandedNodeId::ExpandedNodeId(NodeId nodeId, string_view namespaceUri)
  : mNodeId(nodeId), mNamespaceUri(namespaceUri), mServerIndex(0)
{}

ExpandedNodeId::ExpandedNodeId(NodeId nodeId, uint32_t serverIndex)
  : mNodeId(nodeId), mServerIndex(serverIndex)
{}

ExpandedNodeId::ExpandedNodeId(NodeId nodeId, string_view namespaceUri, uint32_t serverIndex)
  : mNodeId(nodeId), mNamespaceUri(namespaceUri), mServerIndex(serverIndex)
{}

const ua::NodeId& ExpandedNodeId::node_id() const
{
  return mNodeId;
}

ua::NodeId& ExpandedNodeId::node_id()
{
  return mNodeId;
}

const String& ExpandedNodeId::namespace_uri() const
{
  return mNamespaceUri;
}

String& ExpandedNodeId::namespace_uri()
{
  return mNamespaceUri;
}

uint32_t ExpandedNodeId::server_index() const
{
  return mServerIndex;
}

uint32_t& ExpandedNodeId::server_index()
{
  return mServerIndex;
}

bool ExpandedNodeId::is_null() const
{
  return (is_index_based() && is_local() && mNodeId.is_null());
}

bool ExpandedNodeId::is_local() const
{
  return (mServerIndex == 0);
}

bool ExpandedNodeId::is_index_based() const
{
  return mNamespaceUri.empty();
}

ExpandedNodeId ExpandedNodeId::parse(string_view text)
{
  ExpandedNodeId id;
  id.assign_definition(text);
  return id;
}

ExpandedNodeIdResult ExpandedNodeId::try_parse(string_view text) noexcept
{
  try
  {
    return parse(text);
  }
  catch (...)
  {
    return ExpandedNodeIdResult{exception_to_status_code(std::current_exception())};
  }
}

void ExpandedNodeId::assign_definition(string_view definition)
{
  clear();

  // Parse Server Index
  const string_view siPrefix{"svr="};

  if (definition.starts_with(siPrefix))
  {
    auto temp{definition};
    temp.remove_prefix(siPrefix.size());

    uint32_t svr{0};
    if (temp.empty())
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("InvalidExpandedNodeId", "Server index is empty", "ExpandedNodeId"));
    }
    // The whole view: `&temp.back()` as the end excluded the last character and `front()` on an
    // empty view was undefined (security review XML-8).
    auto re = ::std::from_chars(temp.data(), temp.data() + temp.size(), svr);
    if ((re.ec != ::std::errc{}) || (re.ptr == temp.data()))
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("InvalidExpandedNodeId", "Could not parse server index", "ExpandedNodeId")
          .context(ua::ContextKeys::value, std::string(temp)));
    }

    if (svr == 0)
    {
      throw UaException(Status::BadDecodingError,
        make_error_detail(
          "InvalidExpandedNodeId", "svr= format cannot be used for server index zero", "ExpandedNodeId"));
    }

    mServerIndex = svr;

    // re.ptr lies within temp, which begins at definition.data() + siPrefix.size(),
    // so the difference is >= siPrefix.size() (> 0) and fits size_type.
    auto noOfChars = static_cast<size_t>(re.ptr - definition.data());
    auto separator = definition.substr(noOfChars, 1);
    if (separator.empty() || separator.front() != ';')
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build(
          "InvalidExpandedNodeId", "Server index not terminated with semicolon", "ExpandedNodeId")
          .context(ua::ContextKeys::value, std::string(separator)));
    }

    definition = definition.substr(noOfChars + 1);
  }

  // Parse Namespace URI
  const string_view nsUriPrefix{"nsu="};
  bool uriPresent{false};

  if (definition.starts_with(nsUriPrefix))
  {
    uriPresent = true;

    auto temp{definition};
    temp.remove_prefix(nsUriPrefix.size());

    size_t end = temp.find(';');
    if (end == string_view ::npos)
    {
      throw UaException(Status::BadDecodingError,
        make_error_detail(
          "InvalidExpandedNodeId", "Namespace URI not terminated with semicolon", "ExpandedNodeId"));
    }

    mNamespaceUri = temp.substr(0, end);

    end = definition.find(';');
    if (end == string_view ::npos)
    {
      throw UaException(Status::BadDecodingError,
        make_error_detail("InvalidExpandedNodeId",
          "Namespace URI definition not terminated with semicolon",
          "ExpandedNodeId"));
    }
    definition = definition.substr(end + 1);
  }

  mNodeId = NodeId::parse_definition(definition, !uriPresent);
}

std::string ExpandedNodeId::as_definition() const
{
  std::string result;
  if (mServerIndex > 0)
  {
    result += fmt::format("svr={};", mServerIndex);
  }
  if (!mNamespaceUri.empty())
  {
    result += fmt::format("nsu={};", static_cast<string_view>(mNamespaceUri));
  }
  result += mNodeId.as_definition();
  return result;
}

bool ExpandedNodeId::is_remote() const
{
  return !is_local();
}

bool ExpandedNodeId::is_not_index_based() const
{
  return !is_index_based();
}

void ExpandedNodeId::clear()
{
  mNamespaceUri.clear();
  mServerIndex = 0;
  mNodeId.clear();
}

BuiltInTypeId ExpandedNodeId::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExpandedNodeId};
}

NodeId ExpandedNodeId::to_node_id(const NamespaceIndexResolver& resolveNamespaceIndex) const
{
  if (is_index_based())
  {
    return mNodeId;
  }

  NodeId temp{mNodeId};
  temp.namespace_index() = resolveNamespaceIndex(mNamespaceUri);
  return temp;
}

}  // namespace ua
