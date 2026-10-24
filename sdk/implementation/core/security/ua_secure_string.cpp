// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_secure_string.h"

#include "ua_secure_memory.h"

#include <cstring>
#include <utility>

namespace ua
{

namespace
{
std::unique_ptr<char[]> copy_bytes(const char* data, size_t size)
{
  if (size == 0)
    return nullptr;
  auto buffer = std::make_unique<char[]>(size + 1);
  std::memcpy(buffer.get(), data, size);
  buffer[size] = '\0';
  return buffer;
}
}  // namespace

SecureString::SecureString(const char* value) : SecureString(value, std::strlen(value))
{}

SecureString::SecureString(const char* data, size_t size) : mBuffer(copy_bytes(data, size)), mSize(size)
{}

SecureString::SecureString(const SecureString& other)
  : mBuffer(copy_bytes(other.mBuffer.get(), other.mSize)), mSize(other.mSize)
{}

SecureString::SecureString(SecureString&& other) noexcept
  : mBuffer(std::move(other.mBuffer)), mSize(std::exchange(other.mSize, 0))
{}

SecureString& SecureString::operator=(const SecureString& other)
{
  if (this != &other)
  {
    // Copy-and-swap: the replaced storage is scrubbed by the temporary's destructor.
    SecureString replacement{other};
    std::swap(mBuffer, replacement.mBuffer);
    std::swap(mSize, replacement.mSize);
  }
  return *this;
}

SecureString::~SecureString()
{
  scrub();
}

void SecureString::scrub() noexcept
{
  if (mBuffer)
    security::secure_zero(mBuffer.get(), mSize + 1);
}

const char* SecureString::c_str() const noexcept
{
  return mBuffer ? mBuffer.get() : "";
}

std::string_view SecureString::view() const noexcept
{
  return mBuffer ? std::string_view{mBuffer.get(), mSize} : std::string_view{};
}

size_t SecureString::size() const noexcept
{
  return mSize;
}

bool SecureString::empty() const noexcept
{
  return mSize == 0;
}

}  // namespace ua
