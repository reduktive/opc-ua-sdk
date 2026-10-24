// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstract byte-stream interface for sequential and random-access I/O.
/// @ingroup streams

#ifndef UA_STREAM_H
#define UA_STREAM_H

#include "ua_includes.h"

namespace ua
{

/// Abstract interface for a seekable byte stream.
///
/// Models a stream of bytes that concrete devices (files, in-memory buffers, the
/// null sink) implement. Reads and writes operate on raw `std::byte` spans and
/// act at the stream's current position, which advances by the number of bytes
/// transferred. All positions, lengths, and capacities are byte counts.
///
/// Operations are synchronous and blocking. On failure an implementation throws
/// @ref UaException carrying an @ref ErrorDetail (e.g. the stream is closed, an
/// argument is out of range, or the underlying device fails); a capability not
/// offered by a device throws @ref Status::BadNotSupported. Implementations are
/// not thread-safe - serialise access externally if a stream is shared across
/// threads.
///
/// @see FileStream, MemoryStream
/// @ingroup streams
class Stream
{
public:
  /// Default-constructs the abstract base; only derived streams are instantiable.
  Stream() = default;

  /// Destroys the stream, releasing any underlying device or handle.
  virtual ~Stream() = default;

  // Stream carries no data members; the copy/move members are trivial no-ops on the base
  // subobject. They are defaulted (not deleted) so derived streams remain default-constructible
  // and the OutputIterator (which holds a Stream& and assigns through it) stays assignable.

  /// Copy-constructs the base subobject; a no-op as Stream holds no state (see note above).
  Stream(const Stream&) = default;
  /// Copy-assigns the base subobject; a no-op as Stream holds no state (see note above).
  /// @return A reference to this stream.
  Stream& operator=(const Stream&) = default;
  /// Move-constructs the base subobject; a no-op as Stream holds no state (see note above).
  Stream(Stream&&) = default;
  /// Move-assigns the base subobject; a no-op as Stream holds no state (see note above).
  /// @return A reference to this stream.
  Stream& operator=(Stream&&) = default;

  /// Returns whether the stream supports reading.
  /// @return true if the stream supports reading; false otherwise.
  virtual bool can_read() const = 0;

  /// Returns whether the stream supports writing.
  /// @return true if the stream supports writing; false otherwise.
  virtual bool can_write() const = 0;

  /// Returns whether the stream supports seeking to an arbitrary position.
  /// @return true if the stream supports seeking to an arbitrary position; false otherwise.
  virtual bool can_seek() const = 0;

  /// Returns whether the stream currently holds no bytes (length is zero).
  /// @return true if the stream currently holds no bytes; false otherwise.
  virtual bool is_empty() const = 0;

  /// Returns the total number of bytes the stream can hold, in bytes.
  ///
  /// @return The capacity in bytes.
  /// @throws UaException with @ref Status::BadNotSupported if the device has no
  ///         fixed capacity.
  virtual size_t get_capacity() const = 0;

  /// Returns the number of bytes currently stored, in bytes.
  ///
  /// @return The length in bytes.
  virtual size_t get_length() const = 0;

  /// Returns the current read/write position, in bytes from the start.
  ///
  /// @return The position in bytes.
  virtual size_t get_position() const = 0;

  /// Flushes any buffered output to the underlying device.
  virtual void flush() = 0;

  /// Closes the stream and releases the underlying device or handle.
  ///
  /// After closing, further I/O operations fail.
  virtual void close() = 0;

  /// Reads exactly @p dest.size() bytes from the current position into @p dest.
  ///
  /// Advances the position by the number of bytes read. Unlike @ref read, this
  /// requires the full buffer to be filled and treats a short read as an error.
  ///
  /// @param[out] dest Buffer to fill; its full size is read.
  /// @throws UaException carrying an @ref ErrorDetail if fewer than
  ///         @p dest.size() bytes are available or the read fails.
  /// @see read
  virtual void read_all(span<byte> dest) const = 0;

  /// Reads up to @p dest.size() bytes from the current position into @p dest.
  ///
  /// Performs a partial read: copies as many bytes as are available, up to the
  /// buffer size, and advances the position by that amount.
  ///
  /// @param[out] dest Buffer to fill.
  /// @return The number of bytes actually read, in the range [0, dest.size()].
  /// @throws UaException carrying an @ref ErrorDetail if the read fails.
  /// @see read_all
  virtual size_t read(span<byte> dest) const = 0;

  /// Writes all bytes of @p source at the current position.
  ///
  /// Advances the position by @p source.size(). Unlike @ref write, this requires
  /// every byte to be written and treats a short write as an error.
  ///
  /// @param source Bytes to write in full.
  /// @throws UaException carrying an @ref ErrorDetail if fewer than
  ///         @p source.size() bytes are written or the write fails.
  /// @see write
  virtual void write_all(span<const byte> source) = 0;

  /// Writes up to @p source.size() bytes at the current position.
  ///
  /// Performs a partial write and advances the position by the number of bytes
  /// written.
  ///
  /// @param source Bytes to write.
  /// @return The number of bytes actually written, in the range
  ///         [0, source.size()].
  /// @throws UaException carrying an @ref ErrorDetail if the write fails.
  /// @see write_all
  virtual size_t write(span<const byte> source) = 0;

  /// Moves the current position by @p offset bytes, relative to the current
  /// position.
  ///
  /// @param offset Signed byte displacement; negative seeks backward.
  /// @throws UaException with @ref Status::BadOutOfRange if the resulting
  ///         position is negative or past the end of the stream.
  /// @see seek_from_start, seek_from_end
  virtual void seek(int offset) const = 0;

  /// Moves the current position to @p offset bytes from the start of the stream.
  ///
  /// @param offset Absolute byte offset from the start.
  /// @throws UaException with @ref Status::BadOutOfRange if @p offset is past the
  ///         end of the stream.
  /// @see seek, seek_from_end
  virtual void seek_from_start(size_t offset) const = 0;

  /// Moves the current position by @p offset bytes, relative to the end of the
  /// stream.
  ///
  /// @param offset Signed byte displacement from the end; negative seeks backward
  ///        into the stream and zero positions at the end.
  /// @throws UaException with @ref Status::BadOutOfRange if the resulting
  ///         position is negative or past the end of the stream.
  /// @see seek, seek_from_start
  virtual void seek_from_end(int offset) const = 0;

  /// Optional capability: a view over the stream's entire content when that content lives in
  /// externally-owned, immutable, contiguous storage that outlives the stream.
  ///
  /// Returns `std::nullopt` by default - most streams own or mutate their buffer, so a borrowed view
  /// would risk dangling or change underfoot. A stream backed by caller-owned read-only memory (e.g.
  /// @ref memory_stream_device::ExternalReadOnly) overrides this to expose its buffer, letting a
  /// consumer read the content in place instead of copying it out. The view is valid only for as
  /// long as the caller honours that backing storage's lifetime contract.
  ///
  /// @return A view over the full content, or `std::nullopt` if the stream cannot make this guarantee.
  virtual optional<span<const byte>> contiguous_view() const
  {
    return {};
  }
};

}  // namespace ua

#endif  //! UA_STREAM_H
