// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <cerrno>
#include <cstdio>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
#include "ua_file_stream.h"
#include "ua_array.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_status_code.h"
#include "ua_utilities.h"
#include "fmt/format.h"

#ifdef _WIN32
#pragma warning(disable:4996)
#endif

namespace ua
{

namespace
{

FILE* cast_to_file_pointer(void* handle)
{
  return static_cast<FILE*>(handle);
}

}  // namespace

bool FileStream::can_read() const
{
  return true;
}

bool FileStream::can_write() const
{
  return mWritable;
}

bool FileStream::can_seek() const
{
  return true;
}

bool FileStream::is_empty() const
{
  return (get_length() == 0);
}

size_t FileStream::get_capacity() const
{
  throw UaException(Status::BadNotSupported,
    make_error_detail("InvalidArgument", "get_capacity() is not supported for file streams", "FileStream"));
}

size_t FileStream::get_length() const
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("FileReadFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  FILE* fd = cast_to_file_pointer(mFileHandle);

  fpos_t position{};
  int result = fgetpos(fd, &position);
  if (result != 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileReadFailed", "fgetpos() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(result)));
  }

  result = fseek(fd, 0, SEEK_END);
  if (result != 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileSeekFailed", "fseek() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(result)));
  }

  const long int size = ftell(fd);
  if (size < 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileReadFailed", "ftell() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(size)));
  }

  const size_t length = numeric_cast<size_t>(size);

  result = fsetpos(fd, &position);
  if (result != 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileSeekFailed", "fsetpos() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(result)));
  }

  return length;
}

size_t FileStream::get_position() const
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("FileReadFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  FILE* fd = cast_to_file_pointer(mFileHandle);

  const long int size = ftell(fd);
  if (size < 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileReadFailed", "ftell() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(size)));
  }

  return numeric_cast<size_t>(size);
}

void FileStream::set_position(size_t position) const
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("FileSeekFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  const size_t length = get_length();
  if (position > length)
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build("StreamOutOfRange", "Position exceeds file length", "FileStream")
        .context(ua::ContextKeys::actual, std::to_string(position))
        .context(ua::ContextKeys::limit, std::to_string(length))
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  FILE* fd = cast_to_file_pointer(mFileHandle);
  const int result = fseek(fd, numeric_cast<long>(position), SEEK_SET);
  if (result != 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileSeekFailed", "fseek() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::actual, std::to_string(position))
        .context(ua::ContextKeys::fileErrorCode, std::to_string(result)));
  }
}

void FileStream::flush()
{
  FILE* fd = cast_to_file_pointer(mFileHandle);
  if (fflush(fd) != 0)
  {
    const int flushErrno = errno;  // capture before any other call can clobber errno
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileFlushFailed", "fflush() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(flushErrno)));
  }
}

void FileStream::close()
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("FileReadFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  FILE* fd = cast_to_file_pointer(mFileHandle);
  // fclose() releases the stream whether or not it reports a failure (C11 7.21.5.1), so the handle
  // is dropped before the call: after a failed close the destructor must not fclose() a second
  // time, and a second close() reports "not open" rather than touching a freed stream.
  mFileHandle = nullptr;
  const int result = fclose(fd);
  if (result != 0)
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("FileReadFailed", "fclose() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(result)));
  }
}

void FileStream::read_all(span<std::byte> dest) const
{
  read(dest, false);
}

size_t FileStream::read(span<byte> dest) const
{
  return read(dest, true);
}

size_t FileStream::read(span<byte> dest, bool allowPartialRead) const
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("FileReadFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }
  if (dest.empty())
  {
    return 0;
  }
  if (!dest.data())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidArgument", "Read destination buffer is nullptr", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  const size_t contentLength = get_length();
  const size_t position = get_position();
  size_t bytesToRead = dest.size();
  const size_t bytesRemaining = contentLength - position;

  if (bytesToRead > bytesRemaining)
  {
    if (allowPartialRead)
    {
      bytesToRead = bytesRemaining;
    }
    else
    {
      // read_all() requires the full request; failing here (rather than the
      // historical silent zero-read) is what callers such as the binary codec
      // rely on to reject truncated input. See ua_file_stream.h::read_all.
      throw UaException(Status::BadEndOfStream,
        ErrorDetail::build("FileReadFailed", "Requested more bytes than remain in the file", "FileStream")
          .context(ua::ContextKeys::filePath, mFilePath.string())
          .context(ua::ContextKeys::sizeExpected, std::to_string(bytesToRead))
          .context(ua::ContextKeys::sizeActual, std::to_string(bytesRemaining)));
    }
  }

  size_t bytesRead{0};

  if (bytesToRead > 0)
  {
    FILE* fd = cast_to_file_pointer(mFileHandle);
    bytesRead = fread(dest.data(), sizeof(byte), bytesToRead, fd);
    if (bytesToRead != bytesRead)
    {
      throw UaException(Status::BadUnexpectedError,
        ErrorDetail::build("FileReadFailed", "Short read from file", "FileStream")
          .context(ua::ContextKeys::filePath, mFilePath.string())
          .context(ua::ContextKeys::sizeActual, std::to_string(bytesRead))
          .context(ua::ContextKeys::sizeExpected, std::to_string(bytesToRead)));
    }
  }

  return bytesRead;
}

void FileStream::write_all(span<const byte> source)
{
  write(source, false);
}

size_t FileStream::write(span<const byte> source)
{
  return write(source, true);
}

size_t FileStream::write(span<const byte> source, bool allowPartialWrite)
{
  if (!mFileHandle)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("StreamWriteFailed", "File not open", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }
  if (!mWritable)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("StreamReadOnly", "File is not open for writing", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }
  if (!source.data())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidArgument", "Write source buffer is nullptr", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string()));
  }

  FILE* fd = cast_to_file_pointer(mFileHandle);
  const size_t noOfBytesWritten = fwrite(source.data(), sizeof(byte), source.size(), fd);
  if (!allowPartialWrite && (noOfBytesWritten != source.size()))
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build("StreamWriteFailed", "Short write to file", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::sizeActual, std::to_string(noOfBytesWritten))
        .context(ua::ContextKeys::sizeExpected, std::to_string(source.size())));
  }

  return noOfBytesWritten;
}

void FileStream::seek(int offset) const
{
  const int64_t newPosition = numeric_cast<int64_t>(get_position()) + offset;

  set_position(numeric_cast<size_t>(newPosition));
}

void FileStream::seek_from_start(size_t offset) const
{
  return set_position(offset);
}

void FileStream::seek_from_end(int offset) const
{
  const int64_t newPosition = numeric_cast<int64_t>(get_length()) + offset;

  set_position(numeric_cast<size_t>(newPosition));
}

FileStream::FileStream(std::filesystem::path filePath)
  : mFilePath(std::move(filePath)), mFileHandle(nullptr), mWritable(false)
{
  if (mFilePath.empty())
  {
    throw UaException(
      Status::BadInvalidArgument, make_error_detail("InvalidArgument", "File path is empty", "FileStream"));
  }
}

FileStream::FileStream(FileStream&& other) noexcept
  : mFilePath(std::move(other.mFilePath)), mFileHandle(other.mFileHandle), mWritable(other.mWritable)
{
  other.mFileHandle = nullptr;
  other.mWritable = false;
}

FileStream& FileStream::operator=(FileStream&& other) noexcept
{
  if (this != &other)
  {
    if (mFileHandle)
    {
      // Move-assignment is noexcept, so an fclose() failure cannot be surfaced here. Callers that
      // need to observe a flush/close error must call close() before reassigning over an open stream.
      (void)fclose(cast_to_file_pointer(mFileHandle));
    }
    mFilePath = std::move(other.mFilePath);
    mFileHandle = other.mFileHandle;
    mWritable = other.mWritable;
    other.mFileHandle = nullptr;
    other.mWritable = false;
  }
  return *this;
}

StatusCode FileStream::open_for_read()
{
  mWritable = false;

  const std::string mode = get_mode(false, false);
  return open(mode, false);
}

StatusCode FileStream::open_for_exclusive_write()
{
  if (mFileHandle)
  {
    return Status::BadNothingToDo;
  }
  mWritable = true;
#ifdef _WIN32
  HANDLE created =
    CreateFileW(mFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (created == INVALID_HANDLE_VALUE)
  {
    return StatusCode{Status::BadUnknownResponse,
      ErrorDetail::build("FileExclusiveCreateFailed", "CreateFileW(CREATE_NEW) failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(GetLastError()))};
  }
  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(created), 0);
  FILE* handle = fd >= 0 ? _fdopen(fd, "wb") : nullptr;
  if (!handle)
  {
    if (fd >= 0)
      _close(fd);
    else
      CloseHandle(created);
    return StatusCode{Status::BadUnknownResponse,
      ErrorDetail::build("FileExclusiveCreateFailed", "_fdopen() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())};
  }
#else
  const int fd = ::open(mFilePath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  const int openErrno = errno;
  if (fd < 0)
  {
    return StatusCode{Status::BadUnknownResponse,
      ErrorDetail::build("FileExclusiveCreateFailed", "open(O_CREAT|O_EXCL|O_NOFOLLOW) failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(openErrno))};
  }
  FILE* handle = fdopen(fd, "wb");
  if (!handle)
  {
    const int fdopenErrno = errno;
    ::close(fd);
    return StatusCode{Status::BadUnknownResponse,
      ErrorDetail::build("FileExclusiveCreateFailed", "fdopen() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(fdopenErrno))};
  }
#endif
  mFileHandle = handle;
  return Status::Good;
}

StatusCode FileStream::open_for_write(bool eraseExisting, bool append)
{
  mWritable = true;

  const std::string mode = get_mode(true, eraseExisting);
  return open(mode, append);
}

std::string FileStream::get_mode(bool write, bool erase)
{
  std::string mode;

  if (write)
  {
    if (erase)
    {
      mode = "wb+";
    }
    else
    {
      mode = "rb+";
    }
  }
  else
  {
    mode = "rb";
  }

  return mode;
}

StatusCode FileStream::open(string_view mode, bool append)
{
  if (mFileHandle)
  {
    return Status::BadNothingToDo;
  }

#ifdef _WIN32
  FILE* fd = _wfopen(mFilePath.c_str(), std::wstring(mode.begin(), mode.end()).c_str());
#else
  FILE* fd = fopen(mFilePath.c_str(), std::string(mode).c_str());
#endif
  const int openErrno = errno;
  if (!fd)
  {
    return StatusCode{Status::BadUnknownResponse,
      ErrorDetail::build("FileOpenFailed", "fopen() failed", "FileStream")
        .context(ua::ContextKeys::filePath, mFilePath.string())
        .context(ua::ContextKeys::fileErrorCode, std::to_string(openErrno))};
  }

  mFileHandle = fd;

  if (append)
  {
    seek_from_end(0);
  }

  return Status::Good;
}

FileStream::~FileStream()
{
  // A destructor is implicitly noexcept. close() throws a UaException when fclose() fails
  // (e.g. ENOSPC/EIO flushing buffered writes), so calling it here would let that exception
  // escape the noexcept boundary and std::terminate the process during ordinary teardown.
  // Close the handle inline and swallow the result: there is no caller left to report to and
  // nothing actionable to do. Explicit callers that want to observe a flush/close failure must
  // call close() themselves before the object is destroyed.
  if (mFileHandle)
  {
    (void)fclose(cast_to_file_pointer(mFileHandle));  // swallow per the note above (noexcept teardown)
    mFileHandle = nullptr;
  }
}

}  // namespace ua
