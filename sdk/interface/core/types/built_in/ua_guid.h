// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA Guid built-in type: a 16-byte globally unique identifier.
/// @ingroup core_types

#ifndef UA_GUID_H
#define UA_GUID_H

#include <array>
#include <compare>
#include <boost/uuid/uuid.hpp>
#include "ua_built_in_types_fwd_decl.h"
#include "ua_result.h"
#include "ua_includes.h"

namespace ua
{

/// The OPC UA `Guid` built-in type: a 128-bit globally unique identifier.
///
/// Wraps a 16-byte UUID as defined by OPC 10000-6. The string form is the
/// canonical hyphenated representation (e.g.
/// `"72962B91-FA75-4AE6-8D28-B404DC7DAF63"`), and the wire form is the
/// fixed 16-byte little-endian-fields encoding produced by @ref as_ua_binary().
/// A default-constructed Guid is the all-zero (null) value; use @ref generate()
/// or @ref create_and_generate() to obtain a fresh random identifier.
/// @ingroup core_types
class Guid
{
public:
  /// The fixed length of a Guid in bytes (16).
  static const size_t length{16};

  /// Constructs the null (all-zero) Guid.
  Guid();

  /// Removed (API-7.2): a constructor that parses is a throwing conversion in disguise. Use @ref parse
  /// or @ref try_parse. Deleted rather than absent, so a call does not convert silently.
  explicit Guid(string_view definition) = delete;

  /// Parses the text @ref as_string writes: the canonical hyphenated form, for example
  /// `72962B91-FA75-4AE6-8D28-B404DC7DAF63`. `parse(guid.as_string()) == guid` for every Guid.
  ///
  /// @param text The textual UUID.
  /// @return The Guid @p text names.
  /// @throws UaException with @ref Status::BadDecodingError if @p text is not that form.
  /// @see try_parse
  static Guid parse(string_view text);

  /// Parses like @ref parse and reports a malformed text as a bad result instead of throwing.
  ///
  /// @param text The textual UUID.
  /// @return The Guid, or Bad_DecodingError with an @ref ErrorDetail naming the fault.
  [[nodiscard]] static GuidResult try_parse(string_view text) noexcept;
  /// Copies the 16-byte value. A Guid is a trivially copyable value.
  Guid(const Guid&) = default;
  /// Copies the 16-byte value (trivially copyable; the source is unchanged).
  /// @param other Guid whose 16-byte value is copied.
  Guid(Guid&& other) noexcept = default;
  /// Copy-assigns the 16-byte value.
  /// @param other Guid whose 16-byte value is copied.
  /// @return Reference to this Guid.
  Guid& operator=(const Guid& other) = default;
  /// Copy-assigns the 16-byte value (trivially copyable; the source is unchanged).
  /// @param other Guid whose 16-byte value is copied.
  /// @return Reference to this Guid.
  Guid& operator=(Guid&& other) noexcept = default;
  /// Destroys the Guid value.
  ~Guid() = default;

  /// Compares two Guids for byte-wise equality.
  /// @param obj Guid to compare against.
  /// @return `true` when the two 16-byte values are byte-wise equal.
  bool operator==(const Guid& obj) const = default;

  /// Orders two Guids by their 16-byte value.
  /// @param other Guid to compare against.
  /// @return The ordering of this Guid's bytes relative to @p other.
  std::strong_ordering operator<=>(const Guid& other) const;

  /// Swaps the contents of two Guids.
  /// @param obj Guid to swap contents with.
  void swap(Guid& obj) noexcept;

  /// Returns the canonical hyphenated string form of this Guid.
  ///
  /// @return The textual UUID, e.g. `"72962B91-FA75-4AE6-8D28-B404DC7DAF63"`; @ref parse reads it back.
  std::string as_string() const;

  /// Encodes this Guid as its 16-byte OPC UA binary wire form.
  ///
  /// @return The fixed-length, 16-byte encoding per OPC 10000-6.
  /// @see from_ua_binary
  std::array<byte, length> as_ua_binary() const;

  /// Replaces this Guid by decoding its OPC UA binary wire form.
  ///
  /// @param encoding The 16-byte encoding to decode; must be exactly
  ///                 @ref length bytes long.
  /// @see as_ua_binary
  void from_ua_binary(span<const byte> encoding);

  /// Returns `true` if this is the null (all-zero) Guid.
  /// @return `true` when every one of the 16 bytes is zero.
  bool is_null() const;

  /// Returns a hash of this Guid suitable for use in unordered containers.
  ///
  /// @return A hash of the 16-byte value.
  /// @see std::hash<ua::Guid>
  size_t hash() const;

  /// Resets this Guid to the null (all-zero) value.
  void clear();

  /// Replaces this Guid with a freshly generated random (version 4) UUID.
  ///
  /// @see create_and_generate
  void generate();

  /// Returns the OPC UA built-in type identifier for Guid.
  ///
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

  /// Creates a new Guid holding a freshly generated random (version 4) UUID.
  ///
  /// @return A newly generated Guid.
  /// @see generate
  static Guid create_and_generate();

private:
  boost::uuids::uuid mValue;

  static void bytes_to_uuid(span<const byte> bytes, boost::uuids::uuid& uuid);

  static void uuid_to_bytes(const boost::uuids::uuid& uuid, span<byte> bytes);
};

/// Returns the OPC UA type name `"Guid"` for `Guid`.
///
/// Explicit specialisation of the `get_typename` primary template.
///
/// @return The literal `"Guid"`.
template<>
inline string_view get_typename<Guid>()
{
  return "Guid";
}

}  // namespace ua

namespace std
{
/// `std::hash` specialisation for @ref ua::Guid.
///
/// Enables use of @ref ua::Guid as a key in `std::unordered_map` and
/// `std::unordered_set`; delegates to @ref ua::Guid::hash().
template<>
struct hash<ua::Guid>
{
  /// Returns the hash of @p obj.
  /// @param obj Guid to hash.
  /// @return The hash of @p obj, delegating to @ref ua::Guid::hash().
  size_t operator()(const ua::Guid& obj) const
  {
    return obj.hash();
  }
};
}  // namespace std

#endif  // !UA_GUID_H
