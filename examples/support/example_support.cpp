// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "example_support.h"

#include "ua_to_string.h"

#include <boost/asio/signal_set.hpp>

#include <fmt/format.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <future>
#include <memory>
#include <random>
#include <system_error>

namespace examples
{
namespace
{
/// Distinguishes concurrent runs of the same example without depending on the process id, which
/// is spelled differently on each platform.
std::string random_suffix()
{
  std::random_device entropy;
  return fmt::format("{:08x}{:08x}", entropy(), entropy());
}
}  // namespace

void banner(std::string_view name, std::string_view purpose)
{
  fmt::print("=== {} ===\n{}\n\n", name, purpose);
  std::fflush(stdout);
}

void step(int number, std::string_view text)
{
  fmt::print("  {}. {}\n", number, text);
  std::fflush(stdout);
}

void detail(std::string_view text)
{
  fmt::print("     {}\n", text);
  std::fflush(stdout);
}

void finished(std::string_view name)
{
  fmt::print("\nOK  {}\n", name);
  std::fflush(stdout);
}

void print_failure(std::string_view boundary, const ua::StatusCode& status)
{
  fmt::print(stderr, "\nFAILED  {}: {}\n", boundary, ua::to_string(status));
  if (const auto detail = status.shared_detail())
  {
    // The ErrorDetail is part of the status, not a separate log line. Rendering the whole chain
    // here is what makes a failure diagnosable from the console alone.
    fmt::print(stderr, "{}\n", ua::to_string(*detail, 1));
  }
  std::fflush(stderr);
}

int wait_for_shutdown_signal(boost::asio::any_io_executor executor, std::string_view readyMessage)
{
  // Asio delivers signals asynchronously; an example's main() is a blocking foreground program.
  // The promise bridges the two. Capturing the signal_set in the handler keeps it alive until the
  // wait completes.
  auto received = std::make_shared<std::promise<int>>();
  auto future = received->get_future();
  auto signals = std::make_shared<boost::asio::signal_set>(std::move(executor), SIGINT, SIGTERM);
  signals->async_wait([signals, received](const boost::system::error_code& error, int signalNumber)
    { received->set_value(error ? 0 : signalNumber); });

  // Only now is it true, so only now is it said. async_wait above is what replaces the default
  // disposition; announcing readiness before it returned would invite a signal the process cannot
  // yet catch.
  detail(readyMessage);
  return future.get();
}

std::string_view option_value(int argc, char** argv, std::string_view name, std::string_view fallback)
{
  // argv[0] is the program name, and the last argument cannot introduce a value, so the search
  // stops one short of the end.
  for (int index = 1; index + 1 < argc; ++index)
  {
    if (name == argv[index])
    {
      return argv[index + 1];
    }
  }
  return fallback;
}

TemporaryDirectory::TemporaryDirectory(std::string_view prefix)
  : mPath(std::filesystem::temp_directory_path() / fmt::format("{}-{}", prefix, random_suffix()))
{
  std::filesystem::create_directories(mPath);
}

TemporaryDirectory::~TemporaryDirectory()
{
  // A failed cleanup must not throw out of a destructor, and must not stop the example from
  // reporting its own result. The directory is inside the system temporary area either way.
  std::error_code ignored;
  std::filesystem::remove_all(mPath, ignored);
}

}  // namespace examples
