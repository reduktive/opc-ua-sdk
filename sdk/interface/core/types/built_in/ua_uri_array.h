// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Thread-safe URI-indexed registry mapping namespace/server URIs to dense indices.
/// @ingroup core_types

#ifndef UA_URI_ARRAY_H
#define UA_URI_ARRAY_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_string.h"
#include "ua_array.h"
#include "ua_error_detail.h"

namespace ua
{

/// Implementation helpers backing @ref UriArray; not part of the stable public surface.
namespace uri_array_details
{

/// Customization point that extracts the URI key from a stored element.
///
/// The primary template forwards to `element.uri()`; specialise it for element types that
/// expose their URI differently. Used by @ref UriArray to key elements by URI.
///
/// @param t The stored element whose URI key is extracted.
/// @return The element's URI key.
template<typename ElementType>
String get_uri(const ElementType&);

}  // namespace uri_array_details

namespace uri_array_details
{

/// Transparent hash for the URI map, hashing `String` and `string_view` keys identically.
///
/// The `is_transparent` member lets `unordered_map::find(string_view)` look up an entry without
/// first heap-allocating a `String` copy. The URI map is hit on every encode of every type, so
/// eliminating that per-call allocation is the dominant performance win.
/// @ingroup core_types
struct UriHash
{
  using is_transparent = void;  ///< Enables heterogeneous lookup by `string_view`.

  /// Hashes a URI viewed as a `string_view`.
  /// @param s URI to hash.
  /// @return The hash of @p s.
  size_t operator()(string_view s) const noexcept
  {
    return std::hash<string_view>{}(s);
  }

  /// Hashes a URI held as a @ref String, consistently with the `string_view` overload.
  /// @param s URI to hash.
  /// @return The hash of @p s, equal to the `string_view` overload's result for the same text.
  size_t operator()(const String& s) const noexcept
  {
    return std::hash<string_view>{}(string_view{s});
  }
};

/// Transparent equality for the URI map, comparing `String` and `string_view` keys by value.
///
/// The `is_transparent` member pairs with @ref UriHash to enable heterogeneous lookup, so a
/// `string_view` query compares against stored `String` keys without an intervening copy.
/// @ingroup core_types
struct UriEq
{
  using is_transparent = void;  ///< Enables heterogeneous lookup by `string_view`.

  /// Compares two `string_view` URIs for byte-wise equality.
  /// @param a First URI to compare.
  /// @param b Second URI to compare.
  /// @return `true` if @p a and @p b are byte-wise equal.
  bool operator()(string_view a, string_view b) const noexcept
  {
    return a == b;
  }

  /// Compares a stored @ref String URI against a `string_view` query.
  /// @param a Stored @ref String URI.
  /// @param b `string_view` query URI.
  /// @return `true` if @p a and @p b are byte-wise equal.
  bool operator()(const String& a, string_view b) const noexcept
  {
    return string_view{a} == b;
  }

  /// Compares a `string_view` query against a stored @ref String URI.
  /// @param a `string_view` query URI.
  /// @param b Stored @ref String URI.
  /// @return `true` if @p a and @p b are byte-wise equal.
  bool operator()(string_view a, const String& b) const noexcept
  {
    return a == string_view{b};
  }

  /// Compares two stored @ref String URIs for byte-wise equality.
  /// @param a First stored @ref String URI.
  /// @param b Second stored @ref String URI.
  /// @return `true` if @p a and @p b are byte-wise equal.
  bool operator()(const String& a, const String& b) const noexcept
  {
    return a == b;
  }
};

}  // namespace uri_array_details

/// A thread-safe, append-only registry that assigns dense indices to URI-keyed elements.
///
/// Models an OPC UA URI table (such as a NamespaceArray or ServerArray): each element is identified
/// by a URI and assigned a stable, zero-based index in insertion order. Indices are never reused and
/// elements are never removed, so an index stays valid for the lifetime of the registry. Lookups by
/// URI use a transparent hash map to avoid copying the key on every query.
///
/// Every public method serializes against an internal `std::shared_mutex`: read accessors take a
/// shared lock and @ref add_element takes an exclusive lock, so instances are safe to share across
/// threads. The URI of each @p ElementType is obtained through the `uri_array_details::get_uri`
/// customization point, which defaults to calling `element.uri()`.
///
/// @tparam ElementType Stored element type; must expose a URI via the `get_uri` customization point.
/// @tparam IndexType   Unsigned integer type used for indices; its maximum bounds the capacity.
/// @ingroup core_types
template<typename ElementType, typename IndexType>
class UriArray
{
public:
  /// A fully allocated replacement state for one append.
  ///
  /// Preparing may allocate and fail; committing only swaps containers with the live registry. This
  /// is used by higher-level lifecycle coordinators that must finish every fallible collaborator
  /// step before an entry becomes visible. Ordinary callers should use @ref add_element.
  class PreparedAppend
  {
  public:
    /// Move-constructs a prepared state; the source is left empty.
    PreparedAppend(PreparedAppend&&) noexcept = default;
    /// Move-assigns a prepared state; the source is left empty.
    /// @return A reference to this state.
    PreparedAppend& operator=(PreparedAppend&&) noexcept = default;
    ~PreparedAppend() = default;

    PreparedAppend(const PreparedAppend&) = delete;
    PreparedAppend& operator=(const PreparedAppend&) = delete;

    /// Index the prepared element will occupy if committed.
    ///
    /// @return The zero-based index the element takes once committed.
    IndexType index() const noexcept
    {
      return mIndex;
    }

  private:
    friend class UriArray;

    PreparedAppend() = default;

    std::vector<ElementType> mElementArray;
    std::vector<String> mUriArray;
    std::unordered_map<String, IndexType, uri_array_details::UriHash, uri_array_details::UriEq> mUriMap;
    std::size_t mBaseSize{0};
    IndexType mIndex{};
  };

  /// Constructs an empty registry with no entries.
  UriArray() = default;

  /// Returns the index registered for @p uri.
  ///
  /// Takes a shared lock for the duration of the lookup.
  ///
  /// @param uri Namespace/server URI to resolve; compared by value, not retained.
  /// @return The zero-based index assigned to @p uri.
  /// @throws UaException with @ref Status::BadOutOfRange if @p uri is not present.
  IndexType get_index(string_view uri) const;

  /// Returns the URI registered at @p index.
  ///
  /// @param index Zero-based index into the registry.
  /// @return The URI stored at @p index.
  /// @throws UaException with @ref Status::BadOutOfRange if @p index is past the last entry.
  String get_uri(IndexType index) const;

  /// Returns a copy of the element registered at @p index.
  ///
  /// @param index Zero-based index into the registry.
  /// @return A copy of the element stored at @p index.
  /// @throws UaException with @ref Status::BadOutOfRange if @p index is past the last entry.
  ElementType get_element(IndexType index) const;

  /// Returns a copy of the element registered for @p uri.
  ///
  /// Resolves @p uri to its index and then returns the element; equivalent to
  /// `get_element(get_index(uri))`.
  ///
  /// @param uri Namespace/server URI to resolve; compared by value, not retained.
  /// @return A copy of the element registered for @p uri.
  /// @throws UaException with @ref Status::BadOutOfRange if @p uri is not present.
  ElementType get_element(string_view uri) const;

  /// Returns a snapshot of all registered URIs in index order.
  ///
  /// Takes a shared lock and copies the URIs, so the result is a stable view that is unaffected by
  /// concurrent calls to @ref add_element. The element at array position @c i is the URI of index
  /// @c i.
  ///
  /// @return The registered URIs ordered by ascending index.
  Array<String> get_uri_array() const;

  /// Appends @p element and returns the index assigned to it.
  ///
  /// Takes an exclusive lock. The element's URI (via the `get_uri` customization point) must be
  /// unique within the registry and the registry must not be full. On any failure the registry is
  /// left unchanged (strong exception guarantee).
  ///
  /// @param element Element to register; its URI is read through the `get_uri` customization point.
  /// @return The zero-based index newly assigned to @p element.
  /// @throws UaException with @ref Status::BadNotFound if the element's URI is already registered.
  /// @throws UaException with @ref Status::BadInvalidState if the registry has reached the capacity
  ///         imposed by @p IndexType.
  IndexType add_element(ElementType element);

  /// Builds the complete replacement state for appending @p element without changing this registry.
  ///
  /// Validation and every allocation occur here. The returned state can later be installed through
  /// @ref commit_prepared_append without allocation. The registry is unchanged on every exception.
  ///
  /// @param element The element to append once the state is committed.
  /// @return The fully allocated replacement state, ready to install.
  PreparedAppend prepare_append(ElementType element) const;

  /// Installs a state returned by @ref prepare_append using no-throw container swaps.
  ///
  /// Returns false only if another writer changed the registry after preparation. A serialized owner
  /// can therefore treat true as an invariant and keep all fallible work before this call.
  ///
  /// @param prepared A state returned by @ref prepare_append.
  /// @return `true` when the state was installed, `false` when another writer changed the
  ///         registry after it was prepared.
  bool commit_prepared_append(PreparedAppend prepared) noexcept;

private:
  std::vector<ElementType> mElementArray;
  std::vector<String> mUriArray;
  std::unordered_map<String, IndexType, uri_array_details::UriHash, uri_array_details::UriEq> mUriMap;
  mutable std::shared_mutex mMutex;

  optional<IndexType> get_index_internal(string_view uri) const;
};

template<typename ElementType, typename IndexType>
ElementType UriArray<ElementType, IndexType>::get_element(string_view uri) const
{
  return get_element(get_index(uri));
}

template<typename ElementType, typename IndexType>
IndexType UriArray<ElementType, IndexType>::get_index(string_view uri) const
{
  const ReadLock lock(mMutex);

  optional<IndexType> result = get_index_internal(uri);
  if (!result)
  {
    throw UaException{Status::BadOutOfRange,
      ErrorDetail::build("NamespaceNotFound", "Namespace URI not found in URI array", "UriArray")
        .context(ua::ContextKeys::namespaceUri, std::string(uri))};
  }
  return result.value();
}

template<typename ElementType, typename IndexType>
String UriArray<ElementType, IndexType>::get_uri(IndexType index) const
{
  const ReadLock lock(mMutex);

  if (index >= mUriArray.size())
  {
    throw UaException{Status::BadOutOfRange,
      ErrorDetail::build("NamespaceIndexOutOfRange", "Index out of range", "UriArray")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeActual, std::to_string(mUriArray.size()))};
  }
  return mUriArray[index];
}

template<typename ElementType, typename IndexType>
ElementType UriArray<ElementType, IndexType>::get_element(IndexType index) const
{
  const ReadLock lock(mMutex);

  if (index >= mElementArray.size())
  {
    throw UaException{Status::BadOutOfRange,
      ErrorDetail::build("NamespaceIndexOutOfRange", "Index out of range", "UriArray")
        .context(ua::ContextKeys::index, std::to_string(index))
        .context(ua::ContextKeys::sizeActual, std::to_string(mElementArray.size()))};
  }
  return mElementArray[index];
}

template<typename ElementType, typename IndexType>
Array<String> UriArray<ElementType, IndexType>::get_uri_array() const
{
  const ReadLock lock(mMutex);

  return Array<String>{Dimensions{}, mUriArray};
}

template<typename ElementType, typename IndexType>
IndexType UriArray<ElementType, IndexType>::add_element(ElementType element)
{
  const WriteLock lock(mMutex);

  if (get_index_internal(uri_array_details::get_uri(element)).has_value())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("DuplicateNamespaceUri", "URI already exists in URI array", "UriArray")
        .context(ua::ContextKeys::namespaceUri, std::string(uri_array_details::get_uri(element)))};
  }

  if (mUriArray.size() >= std::numeric_limits<IndexType>::max())
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build("NamespaceIndexOutOfRange", "URI array is full", "UriArray")
        .context(ua::ContextKeys::sizeMax, std::to_string(std::numeric_limits<IndexType>::max()))};
  }

  mUriArray.emplace_back(uri_array_details::get_uri(element));
  IndexType index = numeric_cast<IndexType>(mUriArray.size() - 1);

  try
  {
    mElementArray.push_back(element);
  }
  catch (...)
  {
    mUriArray.pop_back();
    throw;
  }

  try
  {
    mUriMap.emplace(std::make_pair(uri_array_details::get_uri(element), index));
  }
  catch (...)
  {
    mUriArray.pop_back();
    mElementArray.pop_back();
    throw;
  }

  return index;
}

template<typename ElementType, typename IndexType>
typename UriArray<ElementType, IndexType>::PreparedAppend UriArray<ElementType, IndexType>::prepare_append(
  ElementType element) const
{
  const ReadLock lock(mMutex);

  const auto uri = uri_array_details::get_uri(element);
  if (get_index_internal(uri).has_value())
  {
    throw UaException{Status::BadAlreadyExists,
      ErrorDetail::build("DuplicateNamespaceRegistration", "URI already exists in URI array", "UriArray")
        .context(ua::ContextKeys::namespaceUri, std::string(uri))};
  }

  const auto maximumEntries = static_cast<std::size_t>(std::numeric_limits<IndexType>::max()) + 1U;
  if (mUriArray.size() >= maximumEntries)
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build("NamespaceTableFull", "URI array has no remaining index", "UriArray")
        .context(ua::ContextKeys::sizeMax, std::to_string(maximumEntries))};
  }

  PreparedAppend prepared;
  prepared.mElementArray = mElementArray;
  prepared.mUriArray = mUriArray;
  prepared.mUriMap = mUriMap;
  prepared.mBaseSize = mUriArray.size();
  prepared.mIndex = numeric_cast<IndexType>(prepared.mBaseSize);
  prepared.mElementArray.push_back(std::move(element));
  prepared.mUriArray.emplace_back(uri);
  prepared.mUriMap.emplace(prepared.mUriArray.back(), prepared.mIndex);
  return prepared;
}

template<typename ElementType, typename IndexType>
bool UriArray<ElementType, IndexType>::commit_prepared_append(PreparedAppend prepared) noexcept
{
  const WriteLock lock(mMutex);
  if (mUriArray.size() != prepared.mBaseSize)
  {
    return false;
  }

  mElementArray.swap(prepared.mElementArray);
  mUriArray.swap(prepared.mUriArray);
  mUriMap.swap(prepared.mUriMap);
  return true;
}

template<typename ElementType, typename IndexType>
optional<IndexType> UriArray<ElementType, IndexType>::get_index_internal(string_view uri) const
{
  optional<IndexType> result;
  auto found = mUriMap.find(uri);  // transparent lookup - no String copy
  if (found != mUriMap.end())
  {
    result = found->second;
  }
  return result;
}

namespace uri_array_details
{

template<typename ElementType>
String get_uri(const ElementType& t)
{
  return t.uri();
}

}  // namespace uri_array_details

}  // namespace ua

#endif  // UA_URI_ARRAY_H
