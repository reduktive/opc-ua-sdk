// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A string that scrubs its buffer on destruction, for secret material.
/// @ingroup security

#ifndef UA_SECURE_STRING_H
#define UA_SECURE_STRING_H

#include "ua_includes.h"

namespace ua
{

struct SecureStringTestAccess;

/// A string that holds secret material in a buffer it owns and zeroes when it is done with it.
///
/// Intended for short-lived secrets such as decrypted passwords. The buffer is overwritten with a
/// non-elidable scrub before it is released, so a compiler cannot optimise the wipe away. A move
/// transfers the buffer: the moved-from instance owns no bytes and nothing is copied or left behind.
/// A copy duplicates the secret into independent storage; copy-assignment scrubs the storage it
/// replaces. The value may contain embedded NUL bytes: @ref size and @ref view report the full
/// length, and @ref c_str is NUL-terminated for callers that need a C string.
///
/// This bounds the time secret bytes remain resident in memory; it is not a guarantee against all
/// disclosure (the value is plain in memory while live and may be paged or duplicated by lower
/// layers). Move-assignment is deleted: a value may be constructed, copied or moved from, but not
/// reassigned in place. The type is not thread-safe.
/// @ingroup security
class SecureString
{
public:
  /// Constructs from a null-terminated C string, copying its bytes.
  ///
  /// @param value Null-terminated source string. Must not be null. The pointed-to bytes are copied;
  ///              no ownership of @p value is taken.
  explicit SecureString(const char* value);

  /// Constructs from @p size bytes at @p data, copying them. Embedded NUL bytes are kept.
  ///
  /// @param data Source bytes; may be null only when @p size is zero.
  /// @param size Number of bytes to copy.
  SecureString(const char* data, size_t size);

  /// Copy-constructs, duplicating the secret into independent storage.
  /// @param other Secret whose bytes are copied into this object.
  SecureString(const SecureString& other);

  /// Move-constructs, taking @p other's buffer. @p other is left empty and owns no bytes.
  /// @param other Secret whose buffer is transferred; left empty.
  SecureString(SecureString&& other) noexcept;

  /// Copy-assigns, duplicating the secret into independent storage; the storage it replaces is scrubbed.
  /// @param other Secret whose bytes replace this object's bytes.
  /// @return This object after assignment.
  SecureString& operator=(const SecureString& other);

  /// Deleted: a SecureString may not be move-assigned in place.
  SecureString& operator=(SecureString&& other) noexcept = delete;

  /// Destroys the string, zeroing its buffer so the secret does not linger.
  ~SecureString();

  /// Returns a pointer to the NUL-terminated value.
  ///
  /// @return NUL-terminated buffer owned by this object. Valid until the string is destroyed, moved
  ///         from or assigned; never null (empty yields "").
  const char* c_str() const noexcept;

  /// The value with its full length, embedded NUL bytes included.
  /// @return A view borrowed until destruction, move or assignment.
  std::string_view view() const noexcept;

  /// Number of bytes in the value (embedded NUL bytes included, the terminator excluded).
  /// @return The byte count excluding the terminator.
  size_t size() const noexcept;

  /// Reports whether the value is empty.
  /// @return True when no value bytes are stored.
  bool empty() const noexcept;

private:
  friend struct SecureStringTestAccess;

  std::unique_ptr<char[]> mBuffer;  ///< size + 1 bytes, NUL-terminated; null when empty.
  size_t mSize{0};

  /// Zeroes the owned buffer (size + 1 bytes) without releasing it.
  void scrub() noexcept;
};

}  // namespace ua

#endif  //! UA_SECURE_STRING_H
