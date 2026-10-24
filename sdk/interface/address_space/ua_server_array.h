// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Index-to-URI mapping for the server's `Server.ServerArray` node.
/// @ingroup address_space

#ifndef UA_SERVER_ARRAY_H
#define UA_SERVER_ARRAY_H

#include "ua_uri_array.h"

namespace ua
{

/// Maps server indices to server application URIs for the address space.
///
/// Backs the standard `Server.ServerArray` variable: each entry is a server
/// application URI, and its position is the server index used by
/// `ExpandedNodeId` and `AddReferencesItem.TargetServerUri` to name a remote
/// server. Index 0 is reserved for the local server's own URI, which is added
/// when the address space is initialised.
///
/// URIs are unique within the array; a URI's index is assigned on insertion and
/// never changes. Access is thread-safe - the array is internally synchronised
/// and every method may be called concurrently from any thread.
/// @ingroup address_space
class ServerArray final
{
private:
  class ServerUri
  {
  public:
    explicit ServerUri(String value);

    String uri() const;

  private:
    String mUri;
  };

public:
  /// Returns the index of a registered server URI.
  ///
  /// @param uri Server application URI to look up.
  /// @return The index at which @p uri is registered.
  /// @throws UaException with `Status::BadOutOfRange` if @p uri is not present.
  /// @see add_server_uri, get_server_uri
  uint32_t get_server_index(string_view uri) const;

  /// Returns the server URI registered at an index.
  ///
  /// @param index Server index, in the range `[0, size())`.
  /// @return The server application URI at @p index.
  /// @throws UaException with `Status::BadOutOfRange` if @p index is out of range.
  /// @see get_server_index
  String get_server_uri(uint32_t index) const;

  /// Registers a server URI and returns its index.
  ///
  /// Appends @p uri to the array. The assigned index is stable for the lifetime
  /// of the array and equals the previous size.
  ///
  /// @param uri Server application URI to register; must not already be present.
  /// @return The index assigned to @p uri.
  /// @throws UaException with `Status::BadNotFound` if @p uri is already
  ///         registered, or `Status::BadInvalidState` if the array is full.
  /// @see get_server_index
  uint32_t add_server_uri(string_view uri);

  /// Returns a snapshot of all registered server URIs in index order.
  ///
  /// @return An array whose element at position `i` is the URI for server
  ///         index `i`; this is the value of the `Server.ServerArray` node.
  Array<String> get_server_array() const;

private:
  UriArray<ServerUri, uint32_t> mUriArray;
};

}  // namespace ua

#endif  // UA_SERVER_ARRAY_H
