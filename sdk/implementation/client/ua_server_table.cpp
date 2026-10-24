// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_table.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status.h"

#include <limits>

namespace ua::client
{
namespace
{
constexpr std::string_view source{"client.server_table"};
}

ServerTable::ServerTable(std::vector<std::string> uris, std::uint64_t generation)
  : mUriByIndex(std::move(uris)), mGeneration(generation)
{
  mIndexByUri.reserve(mUriByIndex.size());
  for (std::size_t index = 0; index < mUriByIndex.size(); ++index)
  {
    mIndexByUri.emplace(mUriByIndex[index], static_cast<ServerIndex>(index));
  }
}

std::size_t ServerTable::UriHash::operator()(std::string_view value) const noexcept
{
  return std::hash<std::string_view>{}(value);
}

std::size_t ServerTable::UriHash::operator()(const std::string& value) const noexcept
{
  return operator()(std::string_view{value});
}

std::optional<std::string_view> ServerTable::lookup_uri(ServerIndex index) const noexcept
{
  if (static_cast<std::uint64_t>(index) >= mUriByIndex.size())
  {
    return std::nullopt;
  }
  return std::string_view{mUriByIndex[index]};
}

std::optional<ServerIndex> ServerTable::lookup_index(std::string_view uri) const noexcept
{
  const auto found = mIndexByUri.find(uri);
  return found == mIndexByUri.end() ? std::nullopt : std::optional<ServerIndex>{found->second};
}

ua::Result<std::string> ServerTable::resolve_server_uri(const ua::ExpandedNodeId& expanded) const noexcept
{
  const auto uri = lookup_uri(expanded.server_index());
  if (!uri)
  {
    return ua::Result<std::string>{ua::Status::BadServerIndexInvalid,
      ua::ErrorDetail::build("ServerIndexOutOfRange",
        "ExpandedNodeId ServerIndex is outside the cached ServerArray",
        std::string{source})
        .context(ua::ContextKeys::serverIndex, expanded.server_index())
        .context(ua::ContextKeys::sizeActual, mUriByIndex.size())};
  }
  return ua::Result<std::string>{std::string{*uri}};
}

std::size_t ServerTable::size() const noexcept
{
  return mUriByIndex.size();
}

std::uint64_t ServerTable::generation() const noexcept
{
  return mGeneration;
}

ua::Result<std::shared_ptr<const ServerTable>> ServerTable::create(
  std::vector<std::string> uris, std::uint64_t generation)
{
  if (uris.empty() || uris.front().empty())
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("LocalServerUriMissing",
        "ServerArray must contain the local Server URI at index zero",
        std::string{source})
        .context(ua::ContextKeys::sizeActual, uris.size())};
  }
  if (uris.size() > static_cast<std::uint64_t>(std::numeric_limits<ServerIndex>::max()) + 1)
  {
    return ua::Result<std::shared_ptr<const ServerTable>>{ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build(
        "TooLarge", "ServerArray has more entries than a UInt32 ServerIndex can address", std::string{source})
        .context(ua::ContextKeys::sizeActual, uris.size())};
  }
  return std::shared_ptr<const ServerTable>(new ServerTable(std::move(uris), generation));
}

}  // namespace ua::client
