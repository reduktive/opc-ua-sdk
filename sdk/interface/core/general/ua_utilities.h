// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Free-function and small-type utilities: enum conversions, byte/char pointer
///        reinterpretation, span helpers, Base64, and security-policy lookups.
/// @ingroup general

#ifndef UA_UTILITIES_H
#define UA_UTILITIES_H

#include <chrono>
#include <boost/system/error_code.hpp>
#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_crypto_types.h"

namespace ua
{

namespace utils
{

/// Satisfied by any type that is not a raw pointer.
///
/// Used to select the value-comparison overload of `compare` over the
/// pointer-dereferencing overload.
template<class T>
concept IsNotAPointer = !std::is_pointer_v<T>;

/// Converts a scoped enumerator to a value of its underlying integral type.
///
/// @tparam Enum Enumeration type.
/// @param e Enumerator to convert.
/// @return @p e reinterpreted as its underlying integral type.
template<class Enum>
constexpr std::underlying_type_t<Enum> to_underlying(Enum e) noexcept
{
  return static_cast<std::underlying_type_t<Enum>>(e);
}

/// Constructs an enumerator from a value of its underlying integral type.
///
/// The value is cast unchecked; @p i is not validated against the declared enumerators.
///
/// @tparam Enum Enumeration type to produce.
/// @param i Underlying integral value.
/// @return @p i reinterpreted as an @p Enum.
template<class Enum>
constexpr Enum from_underlying(std::underlying_type_t<Enum> i) noexcept
{
  return static_cast<Enum>(i);
}

/// Converts a scoped enumerator to its underlying value, range-checked against `int32_t`.
///
/// The underlying value is narrowed through `numeric_cast<int32_t>`.
///
/// @tparam Enum Enumeration type.
/// @param e Enumerator to convert.
/// @return The underlying value of @p e.
/// @warning Declared `noexcept`: if the underlying value does not fit in `int32_t` the
///          range check throws `boost::bad_numeric_cast`, which terminates the process.
template<class Enum>
constexpr std::underlying_type_t<Enum> as_int32(Enum e) noexcept
{
  return numeric_cast<int32_t>(static_cast<std::underlying_type_t<Enum>>(e));
}

/// Reinterprets a `byte` pointer as a `const char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const char* bytes_to_chars(const byte* input)
{
  return reinterpret_cast<const char*>(input);
}

/// Reinterprets a `byte` pointer as a `char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline char* bytes_to_chars(byte* input)
{
  return reinterpret_cast<char*>(input);
}

/// Reinterprets a `uint8_t` pointer as a `const char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const char* bytes_to_chars(const uint8_t* input)
{
  return reinterpret_cast<const char*>(input);
}

/// Reinterprets a `uint8_t` pointer as a `char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline char* bytes_to_chars(uint8_t* input)
{
  return reinterpret_cast<char*>(input);
}

/// Reinterprets a `byte` pointer as a `const unsigned char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const unsigned char* bytes_to_unsigned_chars(const byte* input)
{
  return reinterpret_cast<const unsigned char*>(input);
}

/// Reinterprets a `byte` pointer as an `unsigned char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline unsigned char* bytes_to_unsigned_chars(byte* input)
{
  return reinterpret_cast<unsigned char*>(input);
}

/// Reinterprets a `const char` pointer as a `const byte` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const byte* chars_to_bytes(const char* input)
{
  return reinterpret_cast<const byte*>(input);
}

/// Reinterprets a `char` pointer as a `byte` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline byte* chars_to_bytes(char* input)
{
  return reinterpret_cast<byte*>(input);
}

/// Reinterprets a `const unsigned char` pointer as a `const byte` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const byte* unsigned_chars_to_bytes(const unsigned char* input)
{
  return reinterpret_cast<const byte*>(input);
}

/// Reinterprets an `unsigned char` pointer as a `byte` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline byte* unsigned_chars_to_bytes(unsigned char* input)
{
  return reinterpret_cast<byte*>(input);
}

/// Reinterprets a `const unsigned char` pointer as a `const char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const char* unsigned_chars_to_chars(const unsigned char* input)
{
  return reinterpret_cast<const char*>(input);
}

/// Reinterprets an `unsigned char` pointer as a `char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline char* unsigned_chars_to_chars(unsigned char* input)
{
  return reinterpret_cast<char*>(input);
}

/// Reinterprets a `const char` pointer as a `const unsigned char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline const unsigned char* chars_to_unsigned_chars(const char* input)
{
  return reinterpret_cast<const unsigned char*>(input);
}

/// Reinterprets a `char` pointer as an `unsigned char` pointer over the same storage.
///
/// No copy or conversion occurs; the returned pointer aliases @p input.
///
/// @param input Pointer whose storage is reinterpreted.
/// @return A pointer to the same storage, viewed as the target element type.
inline unsigned char* chars_to_unsigned_chars(char* input)
{
  return reinterpret_cast<unsigned char*>(input);
}

/// Views a `std::string`'s characters as a span of bytes.
///
/// The span aliases @p input's buffer and is valid only while @p input remains alive
/// and unmodified; it does not own or copy the data.
///
/// @param input String whose character data is viewed.
/// @return A read-only byte span over @p input's characters.
inline span<const byte> string_to_span_of_byte(const std::string& input)
{
  return span<const byte>{utils::chars_to_bytes(input.data()), input.size()};
}

/// Views a span of `char` as a span of bytes over the same storage.
///
/// The returned span aliases @p input; no copy occurs.
///
/// @param input Span of `char` whose storage is viewed.
/// @return A read-only byte span over @p input's storage.
inline span<const byte> span_of_char_to_span_of_byte(span<const char> input)
{
  return span<const byte>{utils::chars_to_bytes(input.data()), input.size()};
}

/// Views a span of `uint8_t` as a `string_view` over the same storage.
///
/// The view aliases @p input and is valid only while @p input's storage remains alive;
/// it is not null-terminated.
///
/// @param input Span whose storage is viewed.
/// @return A `string_view` aliasing @p input's storage; not null-terminated.
inline string_view to_string_view(span<const uint8_t> input)
{
  return {reinterpret_cast<const char*>(input.data()), input.size()};
}

/// Views a span of `byte` as a `string_view` over the same storage.
///
/// The view aliases @p input and is valid only while @p input's storage remains alive;
/// it is not null-terminated.
///
/// @param input Span whose storage is viewed.
/// @return A `string_view` aliasing @p input's storage; not null-terminated.
inline string_view to_string_view(span<const byte> input)
{
  return {reinterpret_cast<const char*>(input.data()), input.size()};
}

/// Compares two non-pointer values for equality using `operator==`.
///
/// @tparam T Non-pointer value type, constrained by the `IsNotAPointer` concept.
/// @param a First value to compare.
/// @param b Second value to compare.
/// @return `true` if @p a equals @p b.
template<typename T>
  requires IsNotAPointer<T>
bool compare(const T& a, const T& b)
{
  return (a == b);
}

/// Compares two pointers by the values they point to, treating null as a distinct case.
///
/// Two null pointers compare equal; a null and a non-null compare unequal; otherwise the
/// pointed-to values are compared with `operator==`. Neither pointer is taken to own its
/// target.
///
/// @tparam T Pointed-to type.
/// @param a First pointer; may be null.
/// @param b Second pointer; may be null.
/// @return `true` if both are null, or both are non-null and `*a == *b`.
template<typename T>
bool compare(const T* a, const T* b)
{
  if (!a && !b)
  {
    return true;
  }

  if ((!a && b) || (a && !b))
  {
    return false;
  }

  return (*a == *b);
}

/// Compares two `unique_ptr`s by the values they manage.
///
/// Delegates to the raw-pointer overload, so two empty pointers compare equal.
///
/// @tparam T Managed type.
/// @param a First smart pointer to compare.
/// @param b Second smart pointer to compare.
/// @return `true` if both are empty, or both manage objects that compare equal.
template<typename T>
bool compare(const std::unique_ptr<T>& a, const std::unique_ptr<T>& b)
{
  return compare(a.get(), b.get());
}

/// Compares two `shared_ptr`s by the values they manage.
///
/// Delegates to the raw-pointer overload, so two empty pointers compare equal.
///
/// @tparam T Managed type.
/// @param a First smart pointer to compare.
/// @param b Second smart pointer to compare.
/// @return `true` if both are empty, or both manage objects that compare equal.
template<typename T>
bool compare(const std::shared_ptr<T>& a, const std::shared_ptr<T>& b)
{
  return compare(a.get(), b.get());
}

/// Reports whether a character is a lowercase ASCII letter.
///
/// @param input Character to test.
/// @return `true` if @p input is in `'a'`..`'z'`.
inline bool is_lower_case_ascii_letter(char input)
{
  return islower(input);
}

/// Reports whether a character is an uppercase ASCII letter.
///
/// @param input Character to test.
/// @return `true` if @p input is in `'A'`..`'Z'`.
inline bool is_upper_case_ascii_letter(char input)
{
  return isupper(input);
}

/// Encodes raw bytes as a standard Base64 string.
///
/// @param input Bytes to encode.
/// @return The Base64 text representation of @p input.
/// @see base64_decode
std::string base64_encode(span<const byte> input);

/// Decodes a standard Base64 string back to raw bytes.
///
/// @param input Base64 text to decode.
/// @return The decoded bytes.
/// @see base64_encode
ByteString base64_decode(string_view input);

/// Returns the number of bits in the object representation of `T`.
///
/// @tparam T Type to measure.
/// @return `CHAR_BIT * sizeof(T)`, evaluated at compile time.
template<typename T>
consteval size_t no_of_bits()
{
  return (CHAR_BIT * sizeof(T));
}

/// Reinterprets a pointer as an opaque integer identifier.
///
/// Intended for logging and diagnostics where a stable, human-readable handle for an
/// object is useful. The result is not a portable address and must not be converted back
/// to a pointer.
///
/// @tparam T Pointed-to type.
/// @param ptr Pointer to encode.
/// @return The pointer's bit pattern as a `uintptr_t`.
template<typename T>
uintptr_t pointer_to_id(T* ptr)
{
  return reinterpret_cast<uintptr_t>(ptr);
}

/// A lightweight stopwatch for ad-hoc elapsed-time measurement.
///
/// Measures a single interval against `std::chrono::steady_clock`: @ref start records the
/// origin and @ref stop prints the elapsed duration with a caller-supplied label. Intended
/// for hand profiling, not production timing. Not thread-safe; a single instance must not
/// be driven concurrently.
/// @ingroup general
class Timer
{
public:
  /// Records the current steady-clock time as the start of the measured interval.
  ///
  /// May be called again to restart the measurement from a new origin.
  void start();

  /// Prints the time elapsed since the most recent @ref start to standard output.
  ///
  /// The output is the label followed by the elapsed duration in microseconds.
  ///
  /// @param message Label identifying the measured interval in the output.
  /// @pre @ref start has been called.
  void stop(string_view message);

private:
  std::chrono::steady_clock::time_point mStartTime;
};

/// Throws to report that a requested sub-span lies outside the source span's bounds.
///
/// The shared error path for `safe_sub_span`; the parameters are formatted into the
/// exception message.
///
/// @param offset   Requested sub-span start offset.
/// @param count    Requested sub-span length.
/// @param spanSize Size of the source span.
/// @param location Source location of the originating call, defaulted to the call site.
/// @throws UaException always; this function never returns.
/// @see safe_sub_span
[[noreturn]] void throw_sub_span_out_of_range(
  size_t offset, size_t count, size_t spanSize, source_location location = UA_CURRENT_LOCATION);

/// Returns the bounds-checked sub-span `[offset, offset + count)` of a span.
///
/// Unlike `span::subspan`, the request is validated against the source size before slicing,
/// so an out-of-range request fails loudly rather than producing undefined behaviour. The
/// returned span aliases @p input's storage.
///
/// @tparam T Element type of the span.
/// @param input    Source span to slice.
/// @param offset   Start offset of the sub-span.
/// @param count    Number of elements in the sub-span.
/// @param location Source location of the call, defaulted to the call site and used in the
///                 error message on failure.
/// @return The sub-span `[offset, offset + count)` of @p input.
/// @throws UaException if `offset > input.size()` or `count > input.size() - offset`
///         (via `throw_sub_span_out_of_range`).
/// @see throw_sub_span_out_of_range
template<typename T>
span<T> safe_sub_span(
  span<T> input, size_t offset, size_t count, source_location location = UA_CURRENT_LOCATION)
{
  if ((offset > input.size()) || (count > (input.size() - offset)))
  {
    throw_sub_span_out_of_range(offset, count, input.size(), location);
  }
  return input.subspan(offset, count);
}

/// Formats a Boost.System error code as a human-readable string.
///
/// @param ec Error code to describe.
/// @return The error category name and message for @p ec.
std::string boost_error_to_string(boost::system::error_code ec);

/// Reports whether a security policy uses elliptic-curve cryptography.
///
/// @param securityPolicyId Security policy to classify.
/// @return `true` for ECC-based policies (e.g. the `ECC_*` family).
bool is_ecc_security_policy(ua::SecurityPolicyId securityPolicyId);

/// Reports whether a security policy is deprecated by the OPC UA specification.
///
/// @param securityPolicyId Security policy to classify.
/// @return `true` if @p securityPolicyId is a deprecated policy.
bool is_deprecated_security_policy(ua::SecurityPolicyId securityPolicyId);

/// Maps a security-policy identifier to its standard OPC UA policy URI.
///
/// @param id Security policy to look up.
/// @return The canonical policy URI for @p id.
/// @see get_security_policy_id
String get_security_policy_uri(SecurityPolicyId id);

/// Maps a standard OPC UA security-policy URI to its identifier.
///
/// @param uri Policy URI to resolve.
/// @return The matching `SecurityPolicyId`.
/// @see get_security_policy_uri
SecurityPolicyId get_security_policy_id(String uri);

/// Maps a transport-profile identifier to its standard OPC UA profile URI.
///
/// @param id Transport profile to look up.
/// @return The canonical transport-profile URI for @p id.
String get_transport_profile_uri(TransportProfileId id);

/// Splits a string into substrings on a single-character delimiter.
///
/// Consecutive delimiters yield empty substrings; the delimiter itself is not included in
/// any result element.
///
/// @param input     Text to split.
/// @param delimiter Character that separates fields.
/// @return The substrings between successive delimiters, in order.
std::vector<std::string> split(string_view input, char delimiter);

/// Formats a byte span as a lowercase hexadecimal string.
///
/// @param bytes Bytes to render.
/// @return Two hex digits per byte, in order, with no separators.
std::string bytes_to_hex_string(span<const byte> bytes);

/// Appends every element of a span to the end of a vector.
///
/// Elements are copied; @p source is left unchanged.
///
/// @tparam T Element type of the source span.
/// @tparam U Element type of the destination vector; `T` must be convertible to `U`.
/// @param[in]     source Elements to append.
/// @param[in,out] dest   Vector that the elements are appended to.
template<typename T, typename U>
void append_span_to_vector(span<T>& source, std::vector<U>& dest)
{
  std::copy(source.begin(), source.end(), back_inserter(dest));
}

/// Copies a span of signed 32-bit integers into a vector of their unsigned bit patterns.
///
/// Each element is reinterpreted via `static_cast<uint32_t>`; negative inputs wrap modulo
/// 2^32.
///
/// @param input Signed values to convert.
/// @return A vector of the same length holding the unsigned values.
/// @see span_of_uint32_to_int32
std::vector<uint32_t> span_of_int32_to_uint32(span<const int32_t> input);

/// Copies a span of unsigned 32-bit integers into a vector of their signed bit patterns.
///
/// Each element is reinterpreted via `static_cast<int32_t>`; values above `INT32_MAX` wrap
/// to negatives.
///
/// @param input Unsigned values to convert.
/// @return A vector of the same length holding the signed values.
/// @see span_of_int32_to_uint32
std::vector<int32_t> span_of_uint32_to_int32(span<const uint32_t> input);

}  // namespace utils

}  // namespace ua

#endif  // UA_UTILITIES_H
