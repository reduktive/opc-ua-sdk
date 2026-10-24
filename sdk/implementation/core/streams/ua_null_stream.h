// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Write-only @ref ua::Stream that discards everything written to it.
/// @ingroup streams

#ifndef UA_NULL_STREAM_H
#define UA_NULL_STREAM_H

#include "ua_stream.h"

namespace ua
{

/// A bottomless sink stream: writes are discarded and reads are unsupported.
///
/// Implements the @ref Stream contract as a write-only "null device". Every byte
/// written is discarded but still counted, so @ref get_position advances by the
/// number of bytes written; capacity is effectively unbounded. The stream is not
/// readable and not seekable, and it has no defined length.
///
/// Read operations (@ref read, @ref read_all) and @ref get_length throw
/// @ref UaException carrying a @ref Status::BadNotSupported @ref ErrorDetail.
/// Positions are byte offsets. Instances are not thread-safe; serialise access
/// externally if shared across threads.
///
/// @see Stream, FileStream
/// @ingroup streams
class NullStream : public Stream
{
public:
  NullStream() = default;
  virtual ~NullStream();

  NullStream(const NullStream&) = delete;
  NullStream& operator=(const NullStream&) = delete;
  NullStream(NullStream&&) = delete;
  NullStream& operator=(NullStream&&) = delete;

  /// Returns false: a null stream is never readable.
  /// @return false: a null stream is never readable.
  bool can_read() const override;

  /// Returns true: writes are always accepted (and discarded).
  /// @return true: writes are always accepted (and discarded).
  bool can_write() const override;

  /// Returns false: a null stream cannot seek.
  /// @return false: a null stream cannot seek.
  bool can_seek() const override;

  /// Returns false: a null stream is never considered empty.
  /// @return false: a null stream is never considered empty.
  bool is_empty() const override;

  /// Returns the effectively unbounded capacity (`SIZE_MAX` bytes).
  /// @return The effectively unbounded capacity (`SIZE_MAX` bytes).
  size_t get_capacity() const override;

  /// Not supported by a null stream.
  /// @return Never returns; a null stream has no defined length.
  /// @throws UaException with @ref Status::BadNotSupported; a null stream has no
  ///         defined length.
  size_t get_length() const override;

  /// Returns the current write position in bytes.
  ///
  /// The position is the running total of bytes passed to @ref write and
  /// @ref write_all since construction.
  ///
  /// @return The current write position, in bytes.
  size_t get_position() const override;

  /// Does nothing: there is no buffered data to flush.
  void flush() override;

  /// Does nothing: a null stream holds no resources to release.
  void close() override;

  /// Not supported by a null stream.
  /// @param[out] dest Destination buffer; left untouched.
  /// @throws UaException with @ref Status::BadNotSupported; a null stream cannot
  ///         be read.
  void read_all(span<byte> dest) const override;

  /// Not supported by a null stream.
  /// @param[out] dest Destination buffer; left untouched.
  /// @return Never returns; a null stream cannot be read.
  /// @throws UaException with @ref Status::BadNotSupported; a null stream cannot
  ///         be read.
  size_t read(span<byte> dest) const override;

  /// Discards all of @p source, advancing the position by its size.
  /// @param source Bytes to discard; their contents are ignored.
  /// @post @ref get_position has increased by `source.size()`.
  void write_all(span<const byte> source) override;

  /// Discards all of @p source, advancing the position by its size.
  /// @param source Bytes to discard; their contents are ignored.
  /// @return The number of bytes accepted, always equal to `source.size()`.
  /// @post @ref get_position has increased by `source.size()`.
  size_t write(span<const byte> source) override;

  /// Does nothing: a null stream cannot seek.
  /// @param offset Ignored.
  void seek(int offset) const override;

  /// Does nothing: a null stream cannot seek.
  /// @param offset Ignored.
  void seek_from_start(size_t offset) const override;

  /// Does nothing: a null stream cannot seek.
  /// @param offset Ignored.
  void seek_from_end(int offset) const override;

private:
  size_t mPosition{0};
};

}  // namespace ua

#endif  //! UA_NULL_STREAM_H
