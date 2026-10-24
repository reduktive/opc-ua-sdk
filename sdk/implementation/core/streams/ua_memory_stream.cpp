// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <cassert>
#include "ua_memory_stream.h"
#include "ua_array.h"
#include "ua_error_detail.h"

namespace ua
{

template<typename Device>
MemoryStream<Device>::MemoryStream(Device& device) : mDevice(device)
{}

template<typename Device>
bool MemoryStream<Device>::can_read() const
{
  return true;
}

template<typename Device>
bool MemoryStream<Device>::can_write() const
{
  return mDevice.can_write();
}

template<typename Device>
bool MemoryStream<Device>::can_seek() const
{
  return true;
}

template<typename Device>
bool MemoryStream<Device>::is_empty() const
{
  return mDevice.is_empty();
}

template<typename Device>
size_t MemoryStream<Device>::get_capacity() const
{
  return mDevice.get_capacity();
}

template<typename Device>
size_t MemoryStream<Device>::get_length() const
{
  return mDevice.get_data().size();
}

template<typename Device>
size_t MemoryStream<Device>::get_position() const
{
  return mPosition;
}

template<typename Device>
void MemoryStream<Device>::flush()
{}

template<typename Device>
void MemoryStream<Device>::close()
{}

template<typename Device>
void MemoryStream<Device>::seek(int offset) const
{
  const int64_t newPosition = numeric_cast<int64_t>(mPosition) + offset;

  set_position(numeric_cast<size_t>(newPosition));
}

template<typename Device>
void MemoryStream<Device>::seek_from_start(size_t offset) const
{
  set_position(offset);
}

template<typename Device>
void MemoryStream<Device>::seek_from_end(int offset) const
{
  const int64_t newPosition = numeric_cast<int64_t>(mPosition) + offset;

  return set_position(numeric_cast<size_t>(newPosition));
}

template<typename Device>
void MemoryStream<Device>::set_position(size_t position) const
{
  if (position > mDevice.get_data().size())
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build("StreamOutOfRange", "Stream position is out of range", "MemoryStream")
        .context(ua::ContextKeys::index, std::to_string(position))
        .context(ua::ContextKeys::sizeActual, std::to_string(mDevice.get_data().size())));
  }

  mPosition = position;
}

template<typename Device>
void MemoryStream<Device>::read_all(span<byte> dest) const
{
  read(dest, false);
}

template<typename Device>
size_t MemoryStream<Device>::read(span<byte> dest) const
{
  return read(dest, true);
}

template<typename Device>
void MemoryStream<Device>::write_all(span<const byte> source)
{
  write(source, false);
}

template<typename Device>
size_t MemoryStream<Device>::write(span<const byte> source)
{
  return write(source, true);
}

template<typename Device>
size_t MemoryStream<Device>::read(span<byte> dest, bool allowPartialRead) const
{
  if (dest.empty())
  {
    return 0;
  }

  if (!dest.data())
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidArgument", "Read destination buffer is nullptr", "MemoryStream"));
  }

  size_t lengthToRead = dest.size();
  const span<const byte> data = mDevice.get_data();
  assert(mPosition <= data.size());
  const size_t unreadDataLength = data.size() - mPosition;

  if ((!allowPartialRead) && (lengthToRead > unreadDataLength))
  {
    // Stream::read_all's contract: fewer bytes than requested is an error, never a silent zero-fill.
    // A decoder that ignored a zero return would accept a truncated message as a run of zero values.
    throw UaException(Status::BadEndOfStream,
      ErrorDetail::build("UnexpectedEndOfStream", "Stream ended before the requested bytes", "MemoryStream")
        .context(ua::ContextKeys::sizeExpected, std::to_string(lengthToRead))
        .context(ua::ContextKeys::sizeActual, std::to_string(unreadDataLength)));
  }

  if (unreadDataLength < lengthToRead)
  {
    lengthToRead = unreadDataLength;
  }

  const span<const byte> source(data.data() + mPosition, lengthToRead);
  std::copy(source.begin(), source.end(), dest.begin());
  mPosition += lengthToRead;

  return lengthToRead;
}

template<typename Device>
size_t MemoryStream<Device>::write(span<const byte> source, bool allowPartialWrite)
{
  if (!source.data() && source.size() > 0)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidArgument", "Write source buffer is nullptr", "MemoryStream"));
  }

  size_t lengthToWrite = source.size();
  const size_t capacity = mDevice.get_capacity();
  assert(mPosition <= capacity);
  const size_t spaceRemaining = capacity - mPosition;

  if ((!allowPartialWrite) && (lengthToWrite > spaceRemaining))
  {
    throw UaException(Status::BadUnexpectedError,
      ErrorDetail::build(
        "StreamCapacityExceeded", "Cannot write all data; remaining capacity is insufficient", "MemoryStream")
        .context(ua::ContextKeys::sizeActual, std::to_string(lengthToWrite))
        .context(ua::ContextKeys::sizeMax, std::to_string(spaceRemaining)));
  }

  if (spaceRemaining < lengthToWrite)
  {
    lengthToWrite = spaceRemaining;
  }

  const span<const byte> dataToWrite(source.data(), lengthToWrite);
  mDevice.write(dataToWrite, mPosition);

  mPosition += lengthToWrite;

  return lengthToWrite;
}

template<typename Device>
optional<span<const byte>> MemoryStream<Device>::contiguous_view() const
{
  // Only externally-owned immutable storage may be borrowed in place; owning/writable devices fall
  // back to the base class's nullopt so callers copy the content out instead.
  if constexpr (Device::persistentExternalStorage)
  {
    return mDevice.get_data();
  }
  else
  {
    return {};
  }
}

memory_stream_device::Dynamic::Dynamic() : mCapacity(std::numeric_limits<uint32_t>::max())
{}

memory_stream_device::Dynamic::Dynamic(size_t capacity, bool reserve) : mCapacity(capacity)
{
  if (!mCapacity)
  {
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("InvalidArgument", "Dynamic stream capacity must be non-zero", "MemoryStream"));
  }

  if (reserve)
  {
    mStorage.reserve(mCapacity);
  }
}

bool memory_stream_device::Dynamic::can_write()
{
  return true;
}

bool memory_stream_device::Dynamic::is_empty() const
{
  return mStorage.empty();
}

size_t memory_stream_device::Dynamic::get_capacity() const
{
  return mCapacity;
}

span<const byte> memory_stream_device::Dynamic::get_data() const
{
  return mStorage;
}

void memory_stream_device::Dynamic::write(span<const byte> source, size_t offset)
{
  const size_t endPosition = (offset + source.size());
  assert(endPosition <= mCapacity);

  if (endPosition > mStorage.size())
  {
    mStorage.resize(endPosition);
  }

  const span<byte> dest(mStorage.data() + offset, source.size());
  std::copy(source.begin(), source.end(), dest.begin());
}

std::vector<byte> memory_stream_device::Dynamic::move_storage_out()
{
  return std::move(mStorage);
}

memory_stream_device::ExternalReadOnly::ExternalReadOnly(span<const byte> storage) : mStorage(storage)
{}

bool memory_stream_device::ExternalReadOnly::can_write()
{
  return false;
}

bool memory_stream_device::ExternalReadOnly::is_empty() const
{
  return mStorage.empty();
}

size_t memory_stream_device::ExternalReadOnly::get_capacity() const
{
  return mStorage.size();
}

span<const byte> memory_stream_device::ExternalReadOnly::get_data() const
{
  return mStorage;
}

void memory_stream_device::ExternalReadOnly::write(span<const byte> source, size_t offset)
{
  UA_UNUSED(source);
  UA_UNUSED(offset);
  throw UaException(Status::BadNotSupported,
    make_error_detail("StreamReadOnly", "Cannot write to read-only external memory stream", "MemoryStream"));
}

memory_stream_device::ExternalWritable::ExternalWritable(span<byte> storage, size_t contentLength)
  : mStorage(storage)
{
  if (contentLength > mStorage.size())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("InvalidArgument", "Content length exceeds storage size", "MemoryStream")
        .context(ua::ContextKeys::length, std::to_string(contentLength))
        .context(ua::ContextKeys::sizeMax, std::to_string(storage.size())));
  }

  mContent = span<byte>{storage.data(), contentLength};
}

bool memory_stream_device::ExternalWritable::can_write()
{
  return true;
}

bool memory_stream_device::ExternalWritable::is_empty() const
{
  return mContent.empty();
}

span<const byte> memory_stream_device::ExternalWritable::get_data() const
{
  return mContent;
}

size_t memory_stream_device::ExternalWritable::get_capacity() const
{
  return mStorage.size();
}

void memory_stream_device::ExternalWritable::write(span<const byte> source, size_t offset)
{
  const size_t endPosition = (offset + source.size());
  assert(endPosition <= mStorage.size());

  if (endPosition > mContent.size())
  {
    mContent = span<byte>(mStorage.data(), endPosition);
  }

  const span<byte> dest(mContent.data() + offset, source.size());
  std::copy(source.begin(), source.end(), dest.begin());
}

template class MemoryStream<memory_stream_device::Dynamic>;
template class MemoryStream<memory_stream_device::ExternalReadOnly>;
template class MemoryStream<memory_stream_device::ExternalWritable>;

}  // namespace ua
