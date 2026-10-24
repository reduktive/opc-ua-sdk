// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_table.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_uri.h"  // ua::specNamespaceUri (NS0)
#include "ua_status.h"

#include <limits>

namespace ua::client
{
namespace
{

/// Layer tag stamped on every NamespaceTable ErrorDetail (the `mSource` field).
constexpr std::string_view layer{"client.namespace_table"};

}  // namespace

NamespaceTable::NamespaceTable(
  std::vector<std::string> uris, std::optional<std::uint32_t> urisVersion, std::uint64_t generation)
  : mUriByIndex(std::move(uris)), mUrisVersion(std::move(urisVersion)), mGeneration(generation)
{
  mIndexByUri.reserve(mUriByIndex.size());
  for (std::size_t index = 0; index < mUriByIndex.size(); ++index)
  {
    // emplace keeps the FIRST (lowest-index) occurrence of a duplicated URI; a later duplicate is a
    // no-op. NamespaceArray uniqueness is required by the spec, so a duplicate is a non-conformant
    // server; the advisory is raised by ConnectionImpl, which owns the observer surface.
    mIndexByUri.emplace(mUriByIndex[index], static_cast<NamespaceIndex>(index));
  }
}

std::optional<NamespaceIndex> NamespaceTable::lookup_index(std::string_view uri) const noexcept
{
  const auto found = mIndexByUri.find(uri);
  if (found == mIndexByUri.end())
  {
    return std::nullopt;
  }
  return found->second;
}

std::optional<std::string_view> NamespaceTable::lookup_uri(NamespaceIndex idx) const noexcept
{
  if (idx >= mUriByIndex.size())
  {
    return std::nullopt;
  }
  return std::string_view{mUriByIndex[idx]};
}

std::size_t NamespaceTable::size() const noexcept
{
  return mUriByIndex.size();
}

std::uint64_t NamespaceTable::generation() const noexcept
{
  return mGeneration;
}

std::optional<std::uint32_t> NamespaceTable::uris_version() const noexcept
{
  return mUrisVersion;
}

Result<NodeId> NamespaceTable::translate(const NodeId& node, const NamespaceTable& sourceTable) const noexcept
{
  // Bounds-check first, so the identity fast path and the general path agree on rejecting an
  // out-of-range index rather than the fast path silently passing it through as Good (section 3.1 review).
  const NamespaceIndex sourceIndex = node.namespace_index();
  if (sourceIndex >= sourceTable.mUriByIndex.size())
  {
    return Result<NodeId>{ua::Status::BadNodeIdInvalid,
      ua::ErrorDetail::build("IndexOutOfRange",
        "NodeId namespace index is out of range for the source NamespaceTable",
        std::string{layer})
        .context(ua::ContextKeys::namespaceIndex, sourceIndex)
        .context(ua::ContextKeys::sizeActual, sourceTable.mUriByIndex.size())};
  }

  // Identity fast path: translating against this very snapshot cannot change any index (section 8.5.6), and
  // the index is now known to be in range. The common case after a reconnect that preserved indices
  // carries the same snapshot object on both sides.
  if (this == &sourceTable)
  {
    return node;
  }

  const std::string& uri = sourceTable.mUriByIndex[sourceIndex];
  const auto targetIndex = lookup_index(uri);
  if (!targetIndex)
  {
    return Result<NodeId>{ua::Status::BadNodeIdUnknown,
      ua::ErrorDetail::build("UriUnresolved",
        "namespace URI is not present in the current Session NamespaceArray",
        std::string{layer})
        .context(ua::ContextKeys::namespaceUri, uri)
        .context(ua::ContextKeys::namespaceSourceGeneration, sourceTable.mGeneration)
        .context(ua::ContextKeys::namespaceTargetGeneration, mGeneration)};
  }

  NodeId translated = node;
  translated.namespace_index() = *targetIndex;
  return translated;
}

Result<NodeId> NamespaceTable::resolve_local(const ExpandedNodeId& expanded) const noexcept
{
  const std::string_view uri = expanded.namespace_uri();
  if (uri.empty())
  {
    // CL-VIEW-018: with no URI, the encoded namespace index is authoritative.
    const NodeId& node = expanded.node_id();
    if (node.namespace_index() >= mUriByIndex.size())
    {
      return Result<NodeId>{ua::Status::BadNodeIdInvalid,
        ua::ErrorDetail::build("IndexOutOfRange",
          "ExpandedNodeId namespace index is out of range for this NamespaceArray",
          std::string{layer})
          .context(ua::ContextKeys::namespaceIndex, node.namespace_index())
          .context(ua::ContextKeys::sizeActual, mUriByIndex.size())};
    }
    return node;
  }

  // CL-VIEW-018: a non-empty URI overrides the encoded index (which is 0 on the wire when present).
  const auto localIndex = lookup_index(uri);
  if (!localIndex)
  {
    return Result<NodeId>{
      ua::Status::BadNodeIdUnknown,
      ua::ErrorDetail::build("UriUnresolved",
        "namespace URI is not present in the current Session NamespaceArray",
        std::string{layer})
        .context(ua::ContextKeys::namespaceUri, std::string{uri})  // literal URI preserved verbatim
    };
  }

  NodeId local = expanded.node_id();
  local.namespace_index() = *localIndex;
  return local;
}

std::string NamespaceTable::source_tag_for_namespace_uri(std::string_view uri) const
{
  const std::string_view prefix =
    (mIndexByUri.find(uri) != mIndexByUri.end()) ? "server.namespace." : "server.unknown.";
  std::string tag;
  tag.reserve(prefix.size() + uri.size());
  tag.append(prefix);
  tag.append(uri);
  return tag;
}

Result<std::shared_ptr<const NamespaceTable>> NamespaceTable::create(
  std::vector<std::string> uris, std::optional<std::uint32_t> urisVersion, std::uint64_t generation)
{
  if (uris.empty() || std::string_view{uris.front()} != ua::specNamespaceUri)
  {
    return Result<std::shared_ptr<const NamespaceTable>>{ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build(
        "Ns0Missing", "NamespaceArray is empty or does not begin with the NS0 URI", std::string{layer})
        .context(ua::ContextKeys::sizeActual, uris.size())};
  }

  // NamespaceIndex is a UInt16, so indices 0..65535 are addressable - a longer array cannot be indexed.
  if (uris.size() > std::size_t{std::numeric_limits<NamespaceIndex>::max()} + 1)
  {
    return Result<std::shared_ptr<const NamespaceTable>>{ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("TooLarge",
        "NamespaceArray has more entries than a UInt16 namespace index can address",
        std::string{layer})
        .context(ua::ContextKeys::sizeActual, uris.size())};
  }

  return std::shared_ptr<const NamespaceTable>(
    new NamespaceTable(std::move(uris), std::move(urisVersion), generation));
}

}  // namespace ua::client
