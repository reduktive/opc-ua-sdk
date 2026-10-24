// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Seekable byte @ref ua::Stream backed by a file on the local filesystem.
/// @ingroup streams

#ifndef UA_FILE_STREAM_H
#define UA_FILE_STREAM_H

#include "ua_stream.h"

#include <filesystem>

namespace ua
{

/// A seekable byte stream backed by a file on the local filesystem.
///
/// Wraps a C `FILE*` handle and implements the @ref Stream contract over it. The
/// stream owns its handle: the file is opened by @ref open_for_read or
/// @ref open_for_write and closed by @ref close or the destructor. Move
/// transfers ownership of the handle and leaves the moved-from stream closed;
/// the type is non-copyable.
///
/// Operations throw @ref UaException carrying an @ref ErrorDetail on failure
/// (e.g. the file is not open, the underlying C stdio call fails, or an argument
/// is out of range). Positions and lengths are byte offsets. Instances are not
/// thread-safe; serialise access externally if shared across threads.
///
/// @see Stream
/// @ingroup streams
class FileStream : public Stream
{
private:
  std::filesystem::path mFilePath;
  void* mFileHandle;
  bool mWritable;

  static std::string get_mode(bool write, bool erase);

  StatusCode open(string_view mode, bool append);

  void set_position(size_t position) const;

  size_t read(span<byte> dest, bool allowPartialRead) const;

  size_t write(span<const byte> source, bool allowPartialWrite);

public:
  /// Constructs a closed stream bound to the given filesystem path.
  ///
  /// No file is opened; call @ref open_for_read or @ref open_for_write before
  /// performing I/O. The path is stored by value.
  ///
  /// @param filePath Path to the target file. Must not be empty.
  /// @throws UaException if @p filePath is empty.
  explicit FileStream(std::filesystem::path filePath);

  /// Closes the underlying file if it is still open.
  ~FileStream() override;

  /// Move-constructs from @p other, transferring ownership of its file handle.
  ///
  /// @param other Source stream; left closed after the move.
  FileStream(FileStream&& other) noexcept;

  /// Move-assigns from @p other, closing any handle currently held first.
  ///
  /// @param other Source stream; left closed after the move.
  /// @return Reference to this stream.
  FileStream& operator=(FileStream&& other) noexcept;

  FileStream(const FileStream&) = delete;
  FileStream& operator=(const FileStream&) = delete;

  /// Opens the file for reading at the start of its contents.
  ///
  /// Has no effect and returns @ref Status::BadNothingToDo if the stream is
  /// already open.
  ///
  /// @return @ref Status::Good on success, or a Bad status if the file cannot be
  ///         opened.
  /// @post On success @ref can_write returns false.
  /// @see open_for_write
  StatusCode open_for_read();

  /// Opens the file for reading and writing.
  ///
  /// Has no effect and returns @ref Status::BadNothingToDo if the stream is
  /// already open.
  ///
  /// @param eraseExisting If true, truncates any existing contents to zero
  ///                      length; if false, preserves them.
  /// @param append        If true, positions the stream at the end of the file
  ///                      after opening so writes append.
  /// @return @ref Status::Good on success, or a Bad status if the file cannot be
  ///         opened.
  /// @post On success @ref can_write returns true.
  /// @see open_for_read
  StatusCode open_for_write(bool eraseExisting, bool append);

  /// Creates the file and opens it for writing, refusing an existing path (DEF-5/DEF-7): on POSIX
  /// `O_CREAT|O_EXCL|O_NOFOLLOW` with mode 0600, on Windows `CREATE_NEW`. A planted symlink or a
  /// pre-existing file at the path is an error, never followed or truncated. Fails with
  /// `Bad_UnknownResponse` and the OS error code in the ErrorDetail.
  /// @return Good on exclusive creation, or a rich failure when creation is refused.
  StatusCode open_for_exclusive_write();

  /// Returns true; a file stream always supports reading.
  ///
  /// @return @c true; a file stream always supports reading.
  bool can_read() const override;

  /// Returns true only when the stream was opened via @ref open_for_write.
  ///
  /// @return @c true if the stream was opened for writing; otherwise @c false.
  bool can_write() const override;

  /// Returns true; a file stream always supports seeking.
  ///
  /// @return @c true; a file stream always supports seeking.
  bool can_seek() const override;

  /// Returns true when the file is currently zero bytes long.
  ///
  /// @return @c true if the file is currently zero bytes long.
  /// @throws UaException if the stream is not open or the length cannot be read.
  bool is_empty() const override;

  /// Not supported for file streams.
  ///
  /// @return Never returns; this operation is unsupported for file streams.
  /// @throws UaException with @ref Status::BadNotSupported, always.
  size_t get_capacity() const override;

  /// Returns the total length of the file in bytes.
  ///
  /// Leaves the current read/write position unchanged.
  ///
  /// @return File length in bytes.
  /// @throws UaException if the stream is not open or the length cannot be read.
  size_t get_length() const override;

  /// Returns the current read/write position as a byte offset from the start.
  ///
  /// @return Current position in bytes.
  /// @throws UaException if the stream is not open or the position cannot be read.
  size_t get_position() const override;

  /// Flushes buffered writes to the underlying file.
  void flush() override;

  /// Closes the underlying file and releases its handle.
  ///
  /// @throws UaException if the stream is not open or the file cannot be closed.
  /// @post @ref get_position and other I/O operations throw until the stream is
  ///       reopened.
  void close() override;

  /// Reads exactly @p dest.size() bytes into @p dest, starting at the current
  /// position.
  ///
  /// Advances the position by the number of bytes read. Unlike the partial-read
  /// @ref read(span<byte>)const overload, a short read (fewer bytes available
  /// than requested) is treated as a failure.
  ///
  /// @param[out] dest Destination buffer to fill; its size sets the byte count.
  /// @throws UaException if the stream is not open or @p dest is non-empty with a
  ///         null data pointer; with @ref Status::BadEndOfStream if fewer than
  ///         @p dest.size() bytes remain before end of file.
  void read_all(span<byte> dest) const override;

  /// Reads up to @p dest.size() bytes into @p dest, starting at the current
  /// position.
  ///
  /// Advances the position by the number of bytes read. Reads fewer bytes than
  /// requested when fewer remain before end of file; reads zero from an empty
  /// @p dest.
  ///
  /// @param[out] dest Destination buffer; its size bounds the byte count.
  /// @return Number of bytes actually read.
  /// @throws UaException if the stream is not open or @p dest is non-empty with a
  ///         null data pointer.
  /// @see read_all
  size_t read(span<byte> dest) const override;

  /// Writes all of @p source to the file at the current position.
  ///
  /// Advances the position by the number of bytes written. A short write (fewer
  /// bytes written than supplied) is treated as a failure.
  ///
  /// @param source Bytes to write.
  /// @throws UaException if the stream is not open, not writable, @p source has a
  ///         null data pointer, or not all bytes could be written.
  void write_all(span<const byte> source) override;

  /// Writes up to @p source.size() bytes to the file at the current position.
  ///
  /// Advances the position by the number of bytes written.
  ///
  /// @param source Bytes to write.
  /// @return Number of bytes actually written.
  /// @throws UaException if the stream is not open, not writable, or @p source has
  ///         a null data pointer.
  /// @see write_all
  size_t write(span<const byte> source) override;

  /// Moves the current position by @p offset bytes relative to its present value.
  ///
  /// @param offset Signed byte delta; negative seeks toward the start.
  /// @throws UaException if the stream is not open or the resulting position is
  ///         outside the file.
  /// @see seek_from_start, seek_from_end
  void seek(int offset) const override;

  /// Moves the current position to @p offset bytes from the start of the file.
  ///
  /// @param offset Absolute byte offset from the start.
  /// @throws UaException if the stream is not open or @p offset exceeds the file
  ///         length.
  /// @see seek, seek_from_end
  void seek_from_start(size_t offset) const override;

  /// Moves the current position to @p offset bytes relative to the end of file.
  ///
  /// @param offset Signed byte delta from end of file; negative seeks back into
  ///               the file, zero positions at end of file.
  /// @throws UaException if the stream is not open or the resulting position is
  ///         outside the file.
  /// @see seek, seek_from_start
  void seek_from_end(int offset) const override;
};

}  // namespace ua

#endif  //! UA_FILE_STREAM_H
