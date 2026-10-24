// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_log_sink_implementations.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_log_entry.h"
#include "ua_log_format.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

using namespace ua;

namespace
{

/// Returns a unique, non-existent path under the system temp directory and guarantees its
/// removal when the guard is destroyed.
class TempLogFile
{
public:
  TempLogFile()
  {
    static std::atomic<uint64_t> counter{0};
    mPath = std::filesystem::temp_directory_path() / ("ua_file_log_sink_test_" + std::to_string(::getpid()) +
                                                       "_" + std::to_string(counter.fetch_add(1)) + ".log");
    std::filesystem::remove(mPath);
  }

  ~TempLogFile()
  {
    std::error_code ec;
    std::filesystem::remove(mPath, ec);
  }

  TempLogFile(const TempLogFile&) = delete;
  TempLogFile& operator=(const TempLogFile&) = delete;

  const std::filesystem::path& path() const
  {
    return mPath;
  }

  std::string contents() const
  {
    std::ifstream in{mPath, std::ios::binary};
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
  }

  std::vector<std::string> lines() const
  {
    std::vector<std::string> result;
    std::ifstream in{mPath};
    std::string line;
    while (std::getline(in, line))
    {
      result.push_back(line);
    }
    return result;
  }

private:
  std::filesystem::path mPath;
};

/// Drops the leading `<timestamp> ` prefix so two renderings taken a moment apart can be
/// compared on their deterministic remainder. The timestamp is everything up to (and including)
/// the space that precedes the first `[`.
std::string_view strip_timestamp(std::string_view line)
{
  auto bracket = line.find('[');
  if (bracket == std::string_view::npos)
  {
    return line;
  }
  return line.substr(bracket);
}

LogEntry make_entry(
  LogLevel level, std::string_view category, std::string message, std::span<const LogField> fields)
{
  LogEntry entry;
  entry.level = level;
  entry.category = category;
  entry.message = std::move(message);
  entry.fields = fields;
  return entry;
}

}  // namespace

// A FileLogSink writes the line produced by the shared formatter (same one ConsoleLogSink uses),
// covering one structured field of each LogValue alternative and the space-quoting rule.
TEST(FileLogSink, WritesSharedFormatterLine)
{
  TempLogFile temp;

  const std::array<LogField, 6> fields{{
    {"text", LogValue{std::string_view{"plain"}}},
    {"quoted", LogValue{std::string_view{"has a space"}}},
    {"signed", LogValue{int64_t{-7}}},
    {"unsigned64", LogValue{uint64_t{42}}},
    {"unsigned32", LogValue{uint32_t{9}}},
    {"ratio", LogValue{double{1.5}}},
  }};
  const std::array<LogField, 1> boolField{{{"flag", LogValue{true}}}};

  auto entryA = make_entry(LogLevel::Info, "cat.area", "message body", fields);
  auto entryB = make_entry(LogLevel::Error, "cat.other", "second", boolField);

  // What the shared formatter would emit (the single source of truth that ConsoleLogSink also uses).
  auto expectedA = detail::format_log_line(entryA);
  auto expectedB = detail::format_log_line(entryB);

  {
    FileLogSink sink{temp.path().string()};
    sink.log(entryA);
    sink.log(entryB);
  }

  auto written = temp.lines();
  ASSERT_EQ(written.size(), 2u);

  // Compare on the timestamp-independent remainder (the timestamp differs by the wall clock).
  EXPECT_EQ(strip_timestamp(written[0]), strip_timestamp(expectedA.substr(0, expectedA.size() - 1)));
  EXPECT_EQ(strip_timestamp(written[1]), strip_timestamp(expectedB.substr(0, expectedB.size() - 1)));

  // Concrete spot-checks of the format and the space-quoting rule.
  EXPECT_NE(written[0].find("[    info]"), std::string::npos);
  EXPECT_NE(written[0].find("[cat.area]"), std::string::npos);
  EXPECT_NE(written[0].find("text=plain"), std::string::npos);
  EXPECT_NE(written[0].find("quoted=\"has a space\""), std::string::npos);
  EXPECT_NE(written[0].find("signed=-7"), std::string::npos);
  EXPECT_NE(written[0].find("unsigned64=42"), std::string::npos);
  EXPECT_NE(written[0].find("unsigned32=9"), std::string::npos);
  EXPECT_NE(written[0].find("ratio=1.5"), std::string::npos);
  EXPECT_TRUE(written[0].ends_with("message body"));
  EXPECT_NE(written[1].find("flag=true"), std::string::npos);
}

// The file content is byte-for-byte the shared formatter output (every byte, trailing newline
// included) once the timestamp prefix is accounted for.
TEST(FileLogSink, ContentMatchesFormatterByteForByte)
{
  TempLogFile temp;
  auto entry = make_entry(LogLevel::Debug, "x", "hello", {});
  auto expected = detail::format_log_line(entry);

  {
    FileLogSink sink{temp.path().string()};
    sink.log(entry);
  }

  auto actual = temp.contents();
  ASSERT_FALSE(actual.empty());
  EXPECT_EQ(actual.back(), '\n');  // each entry is newline-terminated
  EXPECT_EQ(strip_timestamp(actual), strip_timestamp(expected));
}

// append=true (the default) preserves existing content across sink instances.
TEST(FileLogSink, AppendPreservesExistingContent)
{
  TempLogFile temp;
  auto first = make_entry(LogLevel::Info, "c", "first", {});
  auto second = make_entry(LogLevel::Info, "c", "second", {});

  {
    FileLogSink sink{temp.path().string(), /*append=*/true};
    sink.log(first);
  }
  {
    FileLogSink sink{temp.path().string(), /*append=*/true};
    sink.log(second);
  }

  auto written = temp.lines();
  ASSERT_EQ(written.size(), 2u);
  EXPECT_TRUE(written[0].ends_with("first"));
  EXPECT_TRUE(written[1].ends_with("second"));
}

// append=false truncates existing content on open.
TEST(FileLogSink, TruncateDiscardsExistingContent)
{
  TempLogFile temp;
  auto first = make_entry(LogLevel::Info, "c", "first", {});
  auto second = make_entry(LogLevel::Info, "c", "second", {});

  {
    FileLogSink sink{temp.path().string(), /*append=*/true};
    sink.log(first);
  }
  {
    FileLogSink sink{temp.path().string(), /*append=*/false};
    sink.log(second);
  }

  auto written = temp.lines();
  ASSERT_EQ(written.size(), 1u);
  EXPECT_TRUE(written[0].ends_with("second"));
}

// Concurrent log() calls from many threads must produce intact, non-interleaved lines and an
// exact line count.
TEST(FileLogSink, ConcurrentWritesAreIntact)
{
  TempLogFile temp;

  constexpr int threads = 8;
  constexpr int perThread = 200;

  {
    FileLogSink sink{temp.path().string(), /*append=*/false};

    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (int t = 0; t < threads; ++t)
    {
      workers.emplace_back(
        [&sink, t]()
        {
          for (int i = 0; i < perThread; ++i)
          {
            // A space in the value exercises the quoting path; the message identifies the writer
            // so we can verify the whole line survived as one unit.
            const std::array<LogField, 1> fields{{{"value", LogValue{std::string_view{"with space"}}}}};
            auto entry = make_entry(LogLevel::Info,
              "concurrent",
              "thread-" + std::to_string(t) + "-line-" + std::to_string(i),
              fields);
            sink.log(entry);
          }
        });
    }
    for (auto& worker : workers)
    {
      worker.join();
    }
  }

  auto written = temp.lines();
  ASSERT_EQ(written.size(), static_cast<size_t>(threads * perThread));

  // Every line must be a complete, uncorrupted record: it carries the quoted field and ends with
  // a well-formed "thread-N-line-M" marker (no interleaving from another thread mid-line).
  for (const auto& line : written)
  {
    EXPECT_NE(line.find("[concurrent]"), std::string::npos);
    EXPECT_NE(line.find("value=\"with space\""), std::string::npos);
    auto marker = line.rfind("thread-");
    ASSERT_NE(marker, std::string::npos);
    EXPECT_NE(line.find("-line-", marker), std::string::npos);
  }
}

// Opening a path inside a non-existent directory must signal the failure by throwing UaException
// carrying an ErrorDetail with the offending path - never silently dropped.
TEST(FileLogSink, OpenFailureThrowsWithDetail)
{
  const std::filesystem::path bad =
    std::filesystem::temp_directory_path() / "ua_file_log_sink_no_such_dir_zzz" / "out.log";
  std::error_code ec;
  ASSERT_FALSE(std::filesystem::exists(bad.parent_path(), ec));

  try
  {
    FileLogSink sink{bad.string()};
    FAIL() << "expected FileLogSink construction to throw for an unopenable path";
  }
  catch (const UaException& ex)
  {
    const auto* detail = ex.detail();
    ASSERT_NE(detail, nullptr);
    // The ErrorDetail must carry the offending path as a structured context fact (never dropped).
    bool foundPath = false;
    for (const auto& named : detail->context)
    {
      if (named.value.find(bad.string()) != std::string::npos)
      {
        foundPath = true;
      }
    }
    EXPECT_TRUE(foundPath) << "ErrorDetail context did not carry the offending file path";
    EXPECT_FALSE(detail->summary.empty());
  }
}

// A string in a log line may be peer-supplied (an endpoint URL, an ERR reason, an application name).
// A control character in a field value would end the line and forge a further entry; a quote would end
// the value. Both are escaped, and a value that needed escaping is quoted.
// @verifies AC-COMP-CORE-LOG-LINE-FORMAT-01-PEER-TEXT-CANNOT-FORGE-A-LOG-LINE
TEST(FormatLogLine, ControlCharactersAndQuotesInAFieldValueAreEscapedAndTheValueQuoted)
{
  const std::string hostile = std::string{"a\nb\"c\\d\x01"} + "e\tf\rg\x7f";
  const std::array<LogField, 1> fields{{{"url", LogValue{std::string_view{hostile}}}}};
  const auto line = detail::format_log_line(make_entry(LogLevel::Warning, "cat", "msg", fields));

  EXPECT_NE(line.find(R"(url="a\nb\"c\\d\x01e\tf\rg\x7f")"), std::string::npos) << line;
  EXPECT_EQ(std::count(line.begin(), line.end(), '\n'), 1) << "one line, ending with its own newline";
  EXPECT_TRUE(line.ends_with(" msg\n"));
}

// The message is escaped the same way (it carries peer text through fmt substitution), so it cannot
// open a second entry either.
// @verifies AC-COMP-CORE-LOG-LINE-FORMAT-01-PEER-TEXT-CANNOT-FORGE-A-LOG-LINE
TEST(FormatLogLine, ControlCharactersInTheMessageAreEscaped)
{
  const auto line = detail::format_log_line(
    make_entry(LogLevel::Error, "cat", "peer said\r\n2026-01-01 00:00:00.000 [    info] [cat] forged", {}));

  EXPECT_NE(line.find(R"(peer said\r\n2026-01-01 00:00:00.000 [    info] [cat] forged)"), std::string::npos)
    << line;
  EXPECT_EQ(std::count(line.begin(), line.end(), '\n'), 1);
}

// Control: ordinary values are unchanged - no quotes without a space or an escape, and a value with a
// space is quoted without any escaping inside it.
// @verifies AC-COMP-CORE-LOG-LINE-FORMAT-01-PEER-TEXT-CANNOT-FORGE-A-LOG-LINE
TEST(FormatLogLine, PlainValuesAreNotEscapedOrQuoted)
{
  const std::array<LogField, 2> fields{{
    {"text", LogValue{std::string_view{"opc.tcp://host:4840/path?q=1"}}},
    {"quoted", LogValue{std::string_view{"has a space"}}},
  }};
  const auto line = detail::format_log_line(make_entry(LogLevel::Info, "cat", "message body", fields));
  EXPECT_NE(
    line.find("text=opc.tcp://host:4840/path?q=1 quoted=\"has a space\" message body\n"), std::string::npos)
    << line;
}

// The three UTF-8 line separators some viewers honour (U+0085, U+2028, U+2029) are escaped like the
// ASCII ones; other non-ASCII text passes through unchanged so UTF-8 stays readable.
// @verifies AC-COMP-CORE-LOG-LINE-FORMAT-01-PEER-TEXT-CANNOT-FORGE-A-LOG-LINE
TEST(FormatLogLine, UnicodeLineSeparatorsAreEscapedAndOtherUtf8PassesThrough)
{
  const std::string hostile = std::string{"a\xC2\x85"} + "b\xE2\x80\xA8" + "c\xE2\x80\xA9" + "d\xC3\xA9";
  const std::array<LogField, 1> fields{{{"name", LogValue{std::string_view{hostile}}}}};
  const auto line = detail::format_log_line(make_entry(LogLevel::Info, "cat", "m", fields));
  const std::string expected = std::string{"name=\"a\\u0085b\\u2028c\\u2029d"} + "\xC3\xA9\"";
  EXPECT_NE(line.find(expected), std::string::npos) << line;
}
