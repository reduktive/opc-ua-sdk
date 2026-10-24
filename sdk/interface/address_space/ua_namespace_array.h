// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-side registry mapping namespace indices to URIs and Namespace instances.
/// @ingroup address_space

#ifndef UA_NAMESPACE_ARRAY_H
#define UA_NAMESPACE_ARRAY_H

#include "ua_uri_array.h"
#include "ua_namespace.h"

namespace ua
{

class AddressSpaceImpl;
class WeakAddressSpace;

namespace uri_array_details
{
/// Reads the URI a Namespace publishes, for the URI-registry template.
///
/// @param nameSpace The namespace whose URI is wanted.
/// @return The namespace's URI.
template<>
String get_uri(const shared_ptr<Namespace>& nameSpace);
}

namespace detail
{
class NamespaceRegistrationCoordinator;
}

/// The address space's table of registered namespaces, keyed by index and URI.
///
/// Holds the ordered list of @ref Namespace instances that back a server's
/// address space. The position of a namespace in this table is its namespace
/// index, the small integer that qualifies every @ref NodeId on the wire;
/// index 0 is OPC UA NS0 (`http://opcfoundation.org/UA/`), installed by
/// initialise(). Lookups are bidirectional: index -> URI/Namespace and
/// URI -> index/Namespace.
///
/// All operations are internally synchronised by a shared mutex, so the table
/// may be queried and extended concurrently from any thread.
/// @ingroup address_space
class NamespaceArray final
{
public:
  /// Returns the namespace registered at @p index, or nullptr if none.
  ///
  /// @param index Namespace index to resolve.
  /// @return The @ref Namespace at @p index, or an empty shared_ptr if @p index
  ///         is out of range. Does not throw.
  shared_ptr<Namespace> get_namespace(uint16_t index) const;

  /// Returns the namespace whose URI equals @p uri.
  ///
  /// @param uri Namespace URI to resolve. Not retained.
  /// @return The matching @ref Namespace.
  /// @throws UaException with @ref Status::BadOutOfRange if no namespace has that URI.
  shared_ptr<Namespace> get_namespace(string_view uri) const;

  /// Returns the index of the namespace whose URI equals @p uri.
  ///
  /// @param uri Namespace URI to resolve. Not retained.
  /// @return The namespace index for @p uri.
  /// @throws UaException with @ref Status::BadOutOfRange if no namespace has that URI.
  uint16_t get_namespace_index(string_view uri) const;

  /// Returns the URI of the namespace registered at @p index.
  ///
  /// @param index Namespace index to resolve.
  /// @return The namespace URI at @p index.
  /// @throws UaException with @ref Status::BadOutOfRange if @p index is out of range.
  String get_namespace_uri(uint16_t index) const;

  /// Returns the registered URIs ordered by namespace index.
  ///
  /// @return The namespace array as published in the `NamespaceArray` Variable,
  ///         element `i` being the URI of namespace index `i`.
  Array<String> get_namespace_array() const;

private:
  friend class AddressSpaceImpl;
  friend class detail::NamespaceRegistrationCoordinator;

  UriArray<shared_ptr<Namespace>, uint16_t> mUriArray;
};

/// Free-function helpers that bridge a @ref NamespaceArray to codec contexts.
namespace namespace_array_utils
{

/// Builds a URI -> namespace-index lookup closure bound to @p addressSpace.
///
/// The returned closure resolves a namespace URI to its index via the address
/// space's @ref NamespaceArray, for use as a codec namespace-mapping callback.
///
/// @param addressSpace Address space to query. Captured by value; the closure
///                     keeps the address space alive for its own lifetime.
/// @return A callable taking a namespace URI and returning its index. The
///         callable throws UaException with @ref Status::BadOutOfRange if the URI
///         is not registered.
/// @see get_index_lookup_function(WeakAddressSpace)
std::function<uint16_t(string_view)> get_index_lookup_function(AddressSpace addressSpace);

/// Builds a URI -> namespace-index lookup closure holding a weak reference to
/// @p addressSpace.
///
/// Like the @ref AddressSpace overload, but captures the address space weakly so
/// the closure does not extend its lifetime; the address space is locked on each
/// invocation.
///
/// @param addressSpace Address space to query, captured weakly.
/// @return A callable taking a namespace URI and returning its index. The
///         callable throws UaException with @ref Status::BadInvalidState if the
///         address space has been destroyed, or @ref Status::BadOutOfRange if the
///         URI is not registered.
/// @see get_index_lookup_function(AddressSpace)
std::function<uint16_t(string_view)> get_index_lookup_function(WeakAddressSpace addressSpace);

}  // namespace namespace_array_utils

}  // namespace ua

#endif  // UA_NAMESPACE_ARRAY_H
