// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_status_code.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

using namespace ua;

namespace
{

/// A unique temp path under the system temp dir, removed when the guard is destroyed.
class TempFile
{
public:
  TempFile()
  {
    static std::atomic<uint64_t> counter{0};
    mPath = std::filesystem::temp_directory_path() / ("ua_file_stream_test_" + std::to_string(::getpid()) +
                                                       "_" + std::to_string(counter.fetch_add(1)) + ".bin");
    std::filesystem::remove(mPath);
  }

  ~TempFile()
  {
    std::error_code ec;
    std::filesystem::remove(mPath, ec);
  }

  const std::filesystem::path& path() const
  {
    return mPath;
  }

private:
  std::filesystem::path mPath;
};

}  // namespace

// On a healthy stream flush() succeeds and the written bytes are durable on disk.
TEST(FileStreamTest, FlushSucceedsAndPersistsData)
{
  const TempFile temp;
  const std::array<std::uint8_t, 5> payload{0x46, 0x47, 0x48, 0x49, 0x4A};

  FileStream stream{temp.path()};
  ASSERT_TRUE(stream.open_for_write(/*eraseExisting=*/true, /*append=*/false).is_good());
  stream.write_all(std::as_bytes(std::span<const std::uint8_t>{payload}));
  EXPECT_NO_THROW(stream.flush());
  stream.close();

  std::ifstream readBack(temp.path(), std::ios::binary);
  const std::vector<char> actual{std::istreambuf_iterator<char>(readBack), std::istreambuf_iterator<char>()};
  ASSERT_EQ(actual.size(), payload.size());
  for (size_t i = 0; i < payload.size(); ++i)
  {
    EXPECT_EQ(static_cast<std::uint8_t>(actual[i]), payload[i]);
  }
}

// flush() must surface an underlying device write failure as a thrown UaException rather
// than silently dropping the buffered data (the cert-err33-c / ErrorDetail-propagation
// contract). /dev/full accepts the open and the buffered write but fails the actual flush
// with ENOSPC, giving deterministic fault injection on Linux (where this suite runs).
// A failed fclose() has still released the stream (C11 7.21.5.1). close() must drop the handle
// before it reports the failure: otherwise the destructor closes the freed stream a second time,
// which glibc reports as a double free and aborts the process. The arm crashes, not fails, without
// the fix, which is the point: the destructor runs at the closing brace.
// The arm needs /dev/full, so it exists on Linux only.
#if defined(__linux__)
// @verifies AC-SVR-SECADMIN-071-PRIVATE-KEY-FILE-IS-CREATED-OWNER-ONLY
TEST(FileStreamTest, CloseFailureReleasesTheHandleSoTheDestructorDoesNotCloseAgain)
{
  {
    FileStream stream{"/dev/full"};
    ASSERT_TRUE(stream.open_for_write(/*eraseExisting=*/false, /*append=*/false).is_good());
    const std::array<std::uint8_t, 64> payload{};
    stream.write_all(std::as_bytes(std::span<const std::uint8_t>{payload}));  // buffered; no I/O yet

    EXPECT_THROW(stream.close(), UaException) << "the flush inside fclose() fails with ENOSPC";
    try
    {
      stream.close();
      FAIL() << "a second close() must report the stream as not open, not touch it";
    }
    catch (const UaException& ex)
    {
      EXPECT_EQ(ex.status_code().as_status(), Status::BadInvalidState);
    }
  }  // ~FileStream: nothing left to close
}
#endif  // __linux__

// The fault injection relies on /dev/full (a Linux-specific device that accepts opens and buffered
// writes but fails the flush with ENOSPC). It does not exist on Windows/macOS, so the test is compiled
// for Linux only; the flush-error propagation path itself is platform-independent SDK code.
#if defined(__linux__)
TEST(FileStreamTest, FlushThrowsWhenUnderlyingWriteFails)
{
  FileStream stream{"/dev/full"};
  // "rb+" (eraseExisting=false): no truncation, opens the existing device read+write.
  ASSERT_TRUE(stream.open_for_write(/*eraseExisting=*/false, /*append=*/false).is_good())
    << "expected /dev/full to be openable for write on this (Linux) host";

  const std::array<std::uint8_t, 64> payload{};
  stream.write_all(std::as_bytes(std::span<const std::uint8_t>{payload}));  // buffered; no I/O yet

  try
  {
    stream.flush();
    FAIL() << "flush() did not throw despite the underlying device being full";
  }
  catch (const UaException& ex)
  {
    EXPECT_TRUE(ex.status_code().is_bad());
  }
}
#endif  // __linux__
