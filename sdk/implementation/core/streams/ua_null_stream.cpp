// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <limits>
#include <cmath>
#include "ua_error_detail.h"
#include "ua_null_stream.h"

namespace ua
{

void NullStream::seek_from_start(size_t offset) const
{
  UA_UNUSED(offset);
}

void NullStream::seek_from_end(int offset) const
{
  UA_UNUSED(offset);
}

void NullStream::seek(int offset) const
{
  UA_UNUSED(offset);
}

void NullStream::close()
{}

void NullStream::flush()
{}

size_t NullStream::get_position() const
{
  return mPosition;
}

size_t NullStream::get_capacity() const
{
  return std::numeric_limits<size_t>::max();
}

size_t NullStream::get_length() const
{
  throw UaException(Status::BadNotSupported,
    make_error_detail("OperationNotSupported", "NullStream does not support get_length()", "NullStream"));
}

bool NullStream::can_seek() const
{
  return false;
}

bool NullStream::can_write() const
{
  return true;
}

bool NullStream::can_read() const
{
  return false;
}

bool NullStream::is_empty() const
{
  return false;
}

NullStream::~NullStream()
{}

void NullStream::read_all(span<byte> dest) const
{
  UA_UNUSED(dest);
  throw UaException(Status::BadNotSupported,
    make_error_detail("OperationNotSupported", "NullStream does not support read_all()", "NullStream"));
}

size_t NullStream::read(span<byte> dest) const
{
  UA_UNUSED(dest);
  throw UaException(Status::BadNotSupported,
    make_error_detail("OperationNotSupported", "NullStream does not support read()", "NullStream"));
}

void NullStream::write_all(span<const byte> source)
{
  mPosition += source.size();
}

size_t NullStream::write(span<const byte> source)
{
  UA_UNUSED(source);
  mPosition += source.size();
  return source.size();
}

}  // namespace ua
