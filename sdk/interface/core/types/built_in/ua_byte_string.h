// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA ByteString built-in type: an owning, resizable sequence of bytes.
/// @ingroup core_types

#ifndef UA_BYTE_STRING_H
#define UA_BYTE_STRING_H

#include <compare>
#include <vector>
#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

/// The OPC UA `ByteString` built-in type: an owning, contiguous sequence of bytes.
///
/// Stores its bytes in a `std::vector<uint8_t>` and exposes a container-like
/// interface (indexing, iteration, `resize`/`reserve`, span conversions) so it
/// can be used wherever raw binary data is carried on the wire - opaque blobs,
/// certificates, nonces, and encoded payloads.
///
/// A `ByteString` distinguishes the *null* state (no value present, as encoded
/// by a length of -1 on the wire) from the *empty* state (a value present with
/// zero bytes); see is_null() versus empty(). A default-constructed instance is
/// null.
/// @ingroup core_types
class ByteString
{
public:
  /// Element type of the byte sequence.
  using value_type = uint8_t;
  /// Mutable iterator over the bytes.
  using iterator = std::vector<uint8_t>::iterator;
  /// Read-only iterator over the bytes.
  using const_iterator = std::vector<uint8_t>::const_iterator;

  /// Constructs a null ByteString (no value present).
  ByteString() = default;
  /// Copies the bytes of the source.
  ByteString(const ByteString&) = default;
  /// Steals the bytes of the source, leaving it null.
  ByteString(ByteString&&) noexcept = default;
  /// Copy-assigns the bytes of the source.
  /// @return `*this`.
  ByteString& operator=(const ByteString&) = default;
  /// Move-assigns the bytes of the source, leaving it null.
  /// @return `*this`.
  ByteString& operator=(ByteString&&) noexcept = default;
  /// Destroys the ByteString, releasing its bytes.
  ~ByteString() = default;

  /// Constructs from a brace-enclosed list of byte values.
  ///
  /// @param init Brace-enclosed byte values copied into the new ByteString.
  ByteString(std::initializer_list<uint8_t> init);

  /// Constructs a ByteString of @p count bytes, each equal to @p value.
  ///
  /// @param count Number of bytes.
  /// @param value Value each byte is initialised to.
  ByteString(size_t count, uint8_t value);

  /// Constructs by taking ownership of an existing byte vector.
  ///
  /// @param data Byte buffer; moved into the new ByteString.
  explicit ByteString(std::vector<uint8_t> data);

  /// Constructs by copying the bytes viewed by @p data.
  ///
  /// @param data View over the source bytes; not retained after construction.
  explicit ByteString(span<const uint8_t> data);

  /// Constructs by copying the bytes viewed by @p data.
  ///
  /// @param data View over the source bytes; not retained after construction.
  ByteString(span<const byte> data);

  /// Constructs by copying the byte range `[first, last)`.
  ///
  /// @tparam InputIt Input iterator whose value type is `uint8_t`.
  /// @param first Iterator to the first byte.
  /// @param last  Iterator one past the last byte.
  template<typename InputIt>
    requires std::same_as<std::iter_value_t<InputIt>, uint8_t>
  ByteString(InputIt first, InputIt last) : mValue(first, last)
  {}

  /// Compares two ByteStrings for byte-wise equality.
  /// @return `true` if the two byte sequences are identical; `false` otherwise.
  bool operator==(const ByteString&) const = default;

  /// Orders two ByteStrings lexicographically by their bytes.
  /// @return The lexicographical ordering of the two byte sequences.
  auto operator<=>(const ByteString&) const = default;

  /// Returns whether this ByteString is null (no value present).
  ///
  /// Distinct from empty(): a null ByteString has no value, whereas an empty one
  /// holds a present value of zero length.
  /// @return `true` if this ByteString is null (no value present); `false` otherwise.
  bool is_null() const;

  /// Returns whether the byte sequence contains no bytes.
  ///
  /// True for both the null state and a present, zero-length value; use is_null()
  /// to distinguish them.
  /// @return `true` if the sequence holds no bytes; `false` otherwise.
  bool empty() const;

  /// Returns the number of bytes held.
  /// @return The number of bytes held.
  size_t size() const;

  /// Resizes the sequence to @p count bytes, value-initialising any new bytes.
  ///
  /// @param count New byte count.
  void resize(size_t count);

  /// Resizes the sequence to @p count bytes, filling any new bytes with @p value.
  ///
  /// @param count New byte count.
  /// @param value Value used to fill bytes appended when growing.
  void resize(size_t count, uint8_t value);

  /// Reserves storage for at least @p capacity bytes without changing size().
  ///
  /// @param capacity Minimum capacity to allocate.
  void reserve(size_t capacity);

  /// Removes all bytes, leaving size() == 0.
  void clear();

  /// Returns a reference to the byte at @p index.
  ///
  /// @param index Zero-based position; must be less than size().
  /// @return Mutable reference to the indexed byte.
  /// @pre @p index < size().
  uint8_t& operator[](size_t index);

  /// Returns a const reference to the byte at @p index.
  ///
  /// @param index Zero-based position; must be less than size().
  /// @return Read-only reference to the indexed byte.
  /// @pre @p index < size().
  const uint8_t& operator[](size_t index) const;

  /// Returns a pointer to the first byte of the contiguous storage.
  ///
  /// @return Pointer to the byte buffer, or `nullptr` if empty. The pointer is
  ///         invalidated by any operation that reallocates (resize, reserve,
  ///         push_back, clear).
  uint8_t* data();

  /// Returns a const pointer to the first byte of the contiguous storage.
  ///
  /// @return Pointer to the byte buffer, or `nullptr` if empty. The pointer is
  ///         invalidated by any operation that reallocates (resize, reserve,
  ///         push_back, clear).
  const uint8_t* data() const;

  /// Returns a mutable iterator to the first byte.
  /// @return Mutable iterator to the first byte.
  std::vector<uint8_t>::iterator begin();

  /// Returns a const iterator to the first byte.
  /// @return Read-only iterator to the first byte.
  std::vector<uint8_t>::const_iterator begin() const;

  /// Returns a mutable iterator one past the last byte.
  /// @return Mutable iterator one past the last byte.
  std::vector<uint8_t>::iterator end();

  /// Returns a const iterator one past the last byte.
  /// @return Read-only iterator one past the last byte.
  std::vector<uint8_t>::const_iterator end() const;

  /// Appends one byte to the end of the sequence.
  ///
  /// @param value Byte to append.
  void push_back(uint8_t value);

  /// Replaces the contents with the byte range `[first, last)`.
  ///
  /// @param first Pointer to the first source byte.
  /// @param last  Pointer one past the last source byte.
  void assign(const uint8_t* first, const uint8_t* last);

  /// Returns a mutable span over the bytes.
  ///
  /// @warning The span is invalidated by any operation that reallocates the
  ///          underlying storage.
  operator span<uint8_t>();

  /// Returns a read-only span over the bytes.
  ///
  /// @warning The span is invalidated by any operation that reallocates the
  ///          underlying storage.
  operator span<const uint8_t>() const;

  /// Returns a mutable `std::byte` span over the bytes.
  ///
  /// @warning The span is invalidated by any operation that reallocates the
  ///          underlying storage.
  operator span<byte>();

  /// Returns a read-only `std::byte` span over the bytes.
  ///
  /// @warning The span is invalidated by any operation that reallocates the
  ///          underlying storage.
  operator span<const byte>() const;

  /// Returns a reference to the underlying byte vector.
  ///
  /// @return Mutable reference to the backing storage, owned by this ByteString.
  std::vector<uint8_t>& payload();

  /// Returns a const reference to the underlying byte vector.
  ///
  /// @return Read-only reference to the backing storage, owned by this ByteString.
  const std::vector<uint8_t>& payload() const;

  /// Returns the built-in type identifier for ByteString.
  ///
  /// @return Always BuiltInTypeId::ByteString.
  static BuiltInTypeId built_in_type_id();

private:
  std::vector<uint8_t> mValue;
};

/// Maps the ByteString type to its OPC UA built-in type identifier.
///
/// @return BuiltInTypeId::ByteString.
template<>
inline BuiltInTypeId built_in_type<ByteString>()
{
  return BuiltInTypeId::ByteString;
}

/// Returns the OPC UA type name for ByteString.
///
/// @return The literal `"ByteString"`.
template<>
inline string_view get_typename<ByteString>()
{
  return "ByteString";
}

}  // namespace ua

#endif  // !UA_BYTE_STRING_H
