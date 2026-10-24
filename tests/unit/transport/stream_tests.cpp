// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// FileStream read/read_all contract tests.
//
// Covers the read_all "fill-or-fail" contract: requesting more bytes than remain
// must throw Status::BadEndOfStream (not silently read zero), while the partial
// read() overload returns the available count without throwing.

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>
#include <string_view>

#include <gtest/gtest.h>

#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_guid.h"
#include "ua_memory_stream.h"
#include "ua_status.h"
#include "ua_status_code.h"

namespace
{

// Writes `content` to a uniquely named temp file and returns its path. The GUID suffix keeps
// the name unique per call: the system temp dir is shared across parallel test shards, so a
// fixed name would race if two tests ever reused it.
std::filesystem::path write_temp_file(std::string_view name, std::string_view content)
{
  const auto path = std::filesystem::temp_directory_path() /
                    (std::string{name} + "_" + ua::Guid::create_and_generate().as_string());
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  return path;
}

TEST(FileStreamReadAll, ReadsExactlyWhenEnoughBytesRemain)
{
  const auto path = write_temp_file("ua_fs_read_all_exact.bin", "hello");
  ua::FileStream stream{path};
  ASSERT_TRUE(stream.open_for_read().is_good());

  std::array<std::byte, 5> buffer{};
  EXPECT_NO_THROW(stream.read_all(std::span<std::byte>{buffer}));
  EXPECT_EQ(stream.get_position(), 5u);

  stream.close();
  std::filesystem::remove(path);
}

TEST(FileStreamReadAll, ThrowsBadEndOfStreamWhenBufferExceedsRemaining)
{
  const auto path = write_temp_file("ua_fs_read_all_short.bin", "hi");
  ua::FileStream stream{path};
  ASSERT_TRUE(stream.open_for_read().is_good());

  // Asking for more than the 2 available bytes must fail, not silently no-op:
  // truncated input has to be rejected (the binary codec relies on this).
  std::array<std::byte, 8> buffer{};
  try
  {
    stream.read_all(std::span<std::byte>{buffer});
    FAIL() << "read_all should have thrown on insufficient data";
  }
  catch (const ua::UaException& e)
  {
    EXPECT_EQ(e.status(), ua::Status::BadEndOfStream);
  }
  // The failed read_all must not advance the position.
  EXPECT_EQ(stream.get_position(), 0u);

  stream.close();
  std::filesystem::remove(path);
}

TEST(FileStreamRead, PartialReadReturnsAvailableWithoutThrowing)
{
  const auto path = write_temp_file("ua_fs_partial.bin", "hi");
  ua::FileStream stream{path};
  ASSERT_TRUE(stream.open_for_read().is_good());

  // The partial-read overload returns fewer bytes rather than throwing.
  std::array<std::byte, 8> buffer{};
  std::size_t bytesRead = 0;
  EXPECT_NO_THROW(bytesRead = stream.read(std::span<std::byte>{buffer}));
  EXPECT_EQ(bytesRead, 2u);
  EXPECT_EQ(stream.get_position(), 2u);

  stream.close();
  std::filesystem::remove(path);
}

// --- MemoryStream::contiguous_view (zero-copy capability) ----------------------------------------
// Only a stream over externally-owned immutable storage may expose its buffer for in-place reading;
// owning/writable streams must report no view so consumers copy the content out instead. This is
// what lets the NodeSet importer parse the const NS0 .rodata array without a transient heap copy.

TEST(MemoryStreamContiguousView, ExternalReadOnlyExposesTheWholeBuffer)
{
  const std::array<std::byte, 5> storage{
    std::byte{'<'}, std::byte{'a'}, std::byte{'/'}, std::byte{'>'}, std::byte{0}};
  ua::memory_stream_device::ExternalReadOnly device{std::span<const std::byte>{storage}};
  ua::MemoryStream stream{device};

  const auto view = stream.contiguous_view();
  ASSERT_TRUE(view.has_value());
  // Zero-copy: the view must alias the caller's storage, not a copy of it.
  EXPECT_EQ(view->data(), storage.data());
  EXPECT_EQ(view->size(), storage.size());
}

TEST(MemoryStreamContiguousView, DynamicOwningStreamReportsNoView)
{
  ua::memory_stream_device::Dynamic device{};
  ua::MemoryStream stream{device};

  // An owning/growable buffer must not be borrowed in place; callers fall back to copying.
  EXPECT_FALSE(stream.contiguous_view().has_value());
}

TEST(MemoryStreamContiguousView, ExternalWritableStreamReportsNoView)
{
  std::array<std::byte, 8> storage{};
  ua::memory_stream_device::ExternalWritable device{std::span<std::byte>{storage}};
  ua::MemoryStream stream{device};

  EXPECT_FALSE(stream.contiguous_view().has_value());
}

}  // namespace

// Stream::read_all's contract holds for the in-memory stream as it does for the file stream: a short
// read is Bad_EndOfStream, never a zero-filled buffer.
// @relation(AC-SVR-UASC-064-TRUNCATED-STREAM-IS-A-DECODING-ERROR, scope=function)  // stream arm
TEST(MemoryStreamReadAll, ThrowsBadEndOfStreamWhenBufferExceedsRemaining)
{
  const std::vector<ua::byte> two{static_cast<ua::byte>(0x01), static_cast<ua::byte>(0x02)};
  ua::memory_stream_device::ExternalReadOnly device{two};
  ua::MemoryStream stream{device};

  std::array<ua::byte, 4> destination{};
  try
  {
    stream.read_all(destination);
    FAIL() << "read_all must not zero-fill a short read";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status(), ua::Status::BadEndOfStream);
  }
  EXPECT_EQ(stream.get_position(), 0u) << "nothing is consumed by a refused read";
}
