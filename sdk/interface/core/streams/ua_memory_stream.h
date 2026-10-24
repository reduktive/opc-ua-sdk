// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Seekable byte @ref ua::Stream backed by an in-memory buffer.
/// @ingroup streams

#ifndef UA_MEMORY_STREAM_H
#define UA_MEMORY_STREAM_H

#include "ua_stream.h"

namespace ua
{

/// Storage backends for @ref MemoryStream.
///
/// Each device owns or refers to the byte buffer that a @ref MemoryStream reads
/// from and writes to, and decides whether the stream is writable and how its
/// capacity grows. A device is selected at compile time as the @ref MemoryStream
/// template argument.
namespace memory_stream_device
{

/// A growable, owning in-memory buffer.
///
/// Backs a writable @ref MemoryStream with a `std::vector<byte>` that the device
/// owns and grows on demand up to a fixed capacity. Writes past the current
/// length extend the buffer; the capacity is the hard upper bound and is set at
/// construction. Lengths and capacities are byte counts.
///
/// @see MemoryStream, ExternalWritable, ExternalReadOnly
/// @ingroup streams
class Dynamic
{
public:
  /// Not externally-owned persistent storage: the buffer is device-owned and may grow/reallocate, so
  /// its bytes must never be borrowed past a write or the device's lifetime.
  /// @see Stream::contiguous_view
  static constexpr bool persistentExternalStorage = false;

  /// Constructs a device whose capacity is the maximum 32-bit value and that
  /// reserves no storage up front.
  Dynamic();

  /// Constructs a device with a fixed maximum capacity.
  ///
  /// @param capacity Maximum number of bytes the buffer may grow to, in bytes;
  ///                 must be non-zero.
  /// @param reserve  When true, reserves @p capacity bytes of storage
  ///                 immediately so growth does not reallocate.
  /// @throws UaException carrying an @ref ErrorDetail if @p capacity is zero.
  Dynamic(size_t capacity, bool reserve);

  /// Returns true; a dynamic buffer is always writable.
  /// @return true; a dynamic buffer is always writable.
  static bool can_write();

  /// Returns true when no bytes have been written yet.
  /// @return true when no bytes have been written yet; false otherwise.
  bool is_empty() const;

  /// Returns the maximum number of bytes the buffer may grow to, in bytes.
  /// @return The maximum number of bytes the buffer may grow to, in bytes.
  size_t get_capacity() const;

  /// Returns a view over the bytes written so far.
  ///
  /// The view is valid until the next write or move; it does not extend past the
  /// current length.
  ///
  /// @return A view over the bytes written so far.
  span<const byte> get_data() const;

  /// Moves the underlying storage out of the device.
  ///
  /// @return The owning byte vector. The device is left empty afterwards.
  std::vector<byte> move_storage_out();

  /// Writes @p source into the buffer at @p offset, growing it if needed.
  ///
  /// @param source Bytes to copy in.
  /// @param offset Byte offset at which to place @p source. @p offset plus the
  ///               size of @p source must not exceed the capacity.
  void write(span<const byte> source, size_t offset);

private:
  std::vector<byte> mStorage;
  const size_t mCapacity;
};

/// A writable, non-owning view over caller-provided storage.
///
/// Backs a writable @ref MemoryStream with externally owned memory. The device
/// does not own the buffer: the caller must keep the underlying storage alive for
/// the lifetime of the device and any stream wrapping it. Capacity is the size of
/// the storage span and is fixed; content length tracks how far the buffer has
/// been filled. Lengths and capacities are byte counts.
///
/// @see MemoryStream, Dynamic, ExternalReadOnly
/// @ingroup streams
class ExternalWritable
{
public:
  /// Not eligible for a borrowed contiguous view: although the storage is caller-owned, it is
  /// writable (hence not immutable) and exposes only the populated content, which may not be
  /// NUL-terminated.
  /// @see Stream::contiguous_view
  static constexpr bool persistentExternalStorage = false;

  /// Wraps externally owned writable storage.
  ///
  /// @param storage       Caller-owned buffer the device writes into; must
  ///                      outlive the device.
  /// @param contentLength Number of leading bytes already populated, in bytes;
  ///                      must not exceed the size of @p storage.
  /// @throws UaException carrying an @ref ErrorDetail if @p contentLength exceeds
  ///         the size of @p storage.
  explicit ExternalWritable(span<byte> storage, size_t contentLength = 0);

  /// Returns true; external writable storage is always writable.
  /// @return true; external writable storage is always writable.
  static bool can_write();

  /// Returns true when the populated content length is zero.
  /// @return true when the populated content length is zero; false otherwise.
  bool is_empty() const;

  /// Returns the size of the backing storage, in bytes.
  /// @return The size of the backing storage, in bytes.
  size_t get_capacity() const;

  /// Returns a view over the populated bytes.
  ///
  /// The view refers to the caller-owned storage and is valid only while that
  /// storage is alive.
  ///
  /// @return A view over the populated bytes.
  span<const byte> get_data() const;

  /// Writes @p source into the storage at @p offset, extending the content length
  /// if needed.
  ///
  /// @param source Bytes to copy in.
  /// @param offset Byte offset at which to place @p source. @p offset plus the
  ///               size of @p source must not exceed the storage size.
  void write(span<const byte> source, size_t offset);

private:
  const span<byte> mStorage;
  span<byte> mContent;
};

/// A read-only, non-owning view over caller-provided storage.
///
/// Backs a non-writable @ref MemoryStream with externally owned immutable memory.
/// The device does not own the buffer: the caller must keep the underlying
/// storage alive for the lifetime of the device and any stream wrapping it. Any
/// write attempt fails. Lengths and capacities are byte counts.
///
/// @see MemoryStream, Dynamic, ExternalWritable
/// @ingroup streams
class ExternalReadOnly
{
public:
  /// Externally-owned immutable storage: the buffer belongs to the caller (who must keep it alive),
  /// is never written, and @ref get_data exposes it whole. This is the one device a @ref MemoryStream
  /// can expose through @ref Stream::contiguous_view for in-place reading without a copy.
  static constexpr bool persistentExternalStorage = true;

  /// Wraps externally owned read-only storage.
  ///
  /// @param storage Caller-owned immutable buffer the device reads from; must
  ///                outlive the device.
  explicit ExternalReadOnly(span<const byte> storage);

  /// Returns false; read-only storage cannot be written.
  /// @return false; read-only storage cannot be written.
  static bool can_write();

  /// Returns true when the backing storage is empty.
  /// @return true when the backing storage is empty; false otherwise.
  bool is_empty() const;

  /// Returns the size of the backing storage, in bytes.
  /// @return The size of the backing storage, in bytes.
  size_t get_capacity() const;

  /// Returns a view over the backing storage.
  ///
  /// The view refers to the caller-owned storage and is valid only while that
  /// storage is alive.
  ///
  /// @return A view over the backing storage.
  span<const byte> get_data() const;

  /// Always fails; read-only storage cannot be written.
  ///
  /// @param source Bytes that would be written; ignored, as this device never
  ///               accepts writes.
  /// @param offset Byte offset that would be written to; ignored.
  /// @throws UaException carrying an @ref ErrorDetail; this device never accepts
  ///         writes.
  static void write(span<const byte> source, size_t offset);

private:
  const span<const byte> mStorage;
};

}  // namespace memory_stream_device

/// A seekable byte @ref Stream backed by an in-memory buffer.
///
/// Implements the @ref Stream contract over a storage device from
/// @ref memory_stream_device, selected as the @p Device template argument. The
/// stream holds a non-owning reference to the device: the device (and any
/// external buffer it refers to) must outlive the stream. Reads, writes and seeks
/// move a single byte position; positions and lengths are byte offsets. Whether
/// the stream is writable is delegated to the device.
///
/// Operations throw @ref UaException carrying an @ref ErrorDetail on failure
/// (e.g. seeking past the end of the data, a null buffer argument, exceeding
/// device capacity, or writing to a read-only device). Instances are not
/// thread-safe; serialise access externally if shared across threads.
///
/// @tparam Device Storage backend from @ref memory_stream_device
///                (@ref memory_stream_device::Dynamic,
///                @ref memory_stream_device::ExternalWritable, or
///                @ref memory_stream_device::ExternalReadOnly).
/// @see Stream
/// @ingroup streams
template<typename Device>
class MemoryStream : public Stream
{
private:
  Device& mDevice;
  mutable size_t mPosition{0};

  void set_position(size_t position) const;

  size_t read(span<byte> dest, bool allowPartialRead) const;

  size_t write(span<const byte> source, bool allowPartialWrite);

public:
  /// Wraps @p device, positioned at the start of its data.
  ///
  /// @param device Storage backend the stream reads from and writes to; must
  ///               outlive the stream.
  explicit MemoryStream(Device& device);

  /// Returns true; a memory stream is always readable.
  /// @return true; a memory stream is always readable.
  bool can_read() const override;

  /// Returns true when the backing device is writable.
  /// @return true when the backing device is writable; false otherwise.
  bool can_write() const override;

  /// Returns true; a memory stream is always seekable.
  /// @return true; a memory stream is always seekable.
  bool can_seek() const override;

  /// Returns true when the backing device holds no data.
  /// @return true when the backing device holds no data; false otherwise.
  bool is_empty() const override;

  /// Returns the maximum number of bytes the stream can hold, in bytes.
  /// @return The maximum number of bytes the stream can hold, in bytes.
  size_t get_capacity() const override;

  /// Returns the number of bytes currently stored, in bytes.
  /// @return The number of bytes currently stored, in bytes.
  size_t get_length() const override;

  /// Returns the current byte position within the stream.
  /// @return The current byte position within the stream.
  size_t get_position() const override;

  /// No-op; an in-memory stream has nothing to flush.
  void flush() override;

  /// No-op; an in-memory stream holds no resource to close.
  void close() override;

  /// Reads exactly @p dest.size() bytes into @p dest, advancing the position.
  ///
  /// @param[out] dest Buffer to fill; its size sets the number of bytes read.
  /// @throws UaException carrying an @ref ErrorDetail if fewer bytes than
  ///         requested remain, or if @p dest is non-empty but has no backing
  ///         storage.
  /// @see read
  void read_all(span<byte> dest) const override;

  /// Reads up to @p dest.size() bytes into @p dest, advancing the position.
  ///
  /// Stops early at the end of the data; a partial read is not an error.
  ///
  /// @param[out] dest Buffer to fill; its size sets the maximum bytes read.
  /// @return The number of bytes read, which may be fewer than requested.
  /// @throws UaException carrying an @ref ErrorDetail if @p dest is non-empty but
  ///         has no backing storage.
  /// @see read_all
  size_t read(span<byte> dest) const override;

  /// Writes all of @p source into the stream, advancing the position.
  ///
  /// @param source Bytes to write.
  /// @throws UaException carrying an @ref ErrorDetail if the device is read-only,
  ///         if @p source has no backing storage, or if the write would exceed
  ///         the remaining capacity.
  /// @see write
  void write_all(span<const byte> source) override;

  /// Writes up to the remaining capacity from @p source, advancing the position.
  ///
  /// Stops early when capacity is exhausted; a partial write is not an error.
  ///
  /// @param source Bytes to write.
  /// @return The number of bytes written, which may be fewer than @p source.size().
  /// @throws UaException carrying an @ref ErrorDetail if the device is read-only
  ///         or if @p source has no backing storage.
  /// @see write_all
  size_t write(span<const byte> source) override;

  /// Moves the current position by @p offset bytes, relative to the current
  /// position.
  ///
  /// @param offset Signed byte displacement; negative values seek backwards.
  /// @throws UaException carrying an @ref ErrorDetail if the resulting position
  ///         is negative or past the end of the data.
  void seek(int offset) const override;

  /// Sets the current position to @p offset bytes from the start.
  ///
  /// @param offset Absolute byte position from the start of the data.
  /// @throws UaException carrying an @ref ErrorDetail if @p offset is past the
  ///         end of the data.
  void seek_from_start(size_t offset) const override;

  /// Moves the current position by @p offset bytes, relative to the current
  /// position.
  ///
  /// @param offset Signed byte displacement; negative values seek backwards.
  /// @throws UaException carrying an @ref ErrorDetail if the resulting position
  ///         is negative or past the end of the data.
  void seek_from_end(int offset) const override;

  /// Returns a view over the backing buffer when @p Device is externally-owned immutable storage
  /// (@ref memory_stream_device::ExternalReadOnly); `std::nullopt` for owning/writable devices.
  /// @return A view over the backing buffer, or `std::nullopt` for owning or writable devices.
  /// @see Stream::contiguous_view
  optional<span<const byte>> contiguous_view() const override;
};

}  // namespace ua

#endif  //! UA_MEMORY_STREAM_H
