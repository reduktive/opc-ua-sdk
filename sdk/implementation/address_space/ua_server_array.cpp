// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_array.h"

namespace ua
{

uint32_t ServerArray::get_server_index(string_view uri) const
{
  return mUriArray.get_index(uri);
}

String ServerArray::get_server_uri(uint32_t index) const
{
  return mUriArray.get_uri(index);
}

uint32_t ServerArray::add_server_uri(string_view uri)
{
  return mUriArray.add_element(ServerUri{String{uri}});
}

Array<String> ServerArray::get_server_array() const
{
  return mUriArray.get_uri_array();
}

ServerArray::ServerUri::ServerUri(String value) : mUri(std::move(value))
{}

String ServerArray::ServerUri::uri() const
{
  return mUri;
}
}  // namespace ua
