// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_SUPPORT_H
#define UASDK_EXAMPLE_SUPPORT_H

/// @file
/// @brief Console output, failure rendering, signal waiting, and temporary directories for the
///        SDK example programs.
///
/// Nothing in this header teaches OPC UA. It exists so that every example prints in the same
/// shape and spends its lines on the SDK instead of on plumbing. Anything an SDK user would need
/// to learn - certificates, endpoints, connections, address spaces, subscriptions - stays in the
/// foreground of the examples themselves.

#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>

#include <filesystem>
#include <string>
#include <string_view>

namespace examples
{

/// Prints the example's title and one-line purpose. Call this once, first.
void banner(std::string_view name, std::string_view purpose);

/// Prints one numbered step line. The number is the step's position in `main()`, so console output
/// and the README's "How it works" table can be read side by side.
void step(int number, std::string_view text);

/// Prints an unnumbered continuation line beneath the step above it.
void detail(std::string_view text);

/// Prints the closing line of a successful run.
void finished(std::string_view name);

/// Renders a complete StatusCode and ErrorDetail chain to stderr. Every example calls this in
/// exactly one place: the catch in `main()`.
void print_failure(std::string_view boundary, const ua::StatusCode& status);

/// Announces that the example is ready to be interrupted, then blocks until SIGINT or SIGTERM
/// (Ctrl+C, or the equivalent console event on Windows) and returns the signal number. Returns 0 if
/// the wait was cancelled.
///
/// The ready message is a parameter rather than something the caller prints first because the two
/// have to happen in this order. Anything watching for that line - the example tests do exactly
/// this - can signal the instant it appears, and a handler armed a moment later is too late: the
/// signal takes its default action and the process dies instead of shutting down. Printing after
/// arming, inside one call, is what makes that ordering impossible to get wrong.
///
/// @param executor     The executor the signal wait is posted to, normally `runtime.executor()`.
/// @param readyMessage Printed as a detail line once the handler is armed.
int wait_for_shutdown_signal(boost::asio::any_io_executor executor, std::string_view readyMessage);

/// Returns the value of a `--name value` command-line option, or @p fallback if it is absent.
///
/// Deliberately minimal: the examples accept a couple of named options so that a reader whose
/// machine already has something on the default port is not stuck, and so the behaviour tests can
/// give each example a port of its own. Anything richer than this belongs in the application, not
/// in an example - see `examples/reference_server`, which uses a real option parser.
[[nodiscard]] std::string_view option_value(
  int argc, char** argv, std::string_view name, std::string_view fallback);

/// A uniquely named directory that is deleted when this object goes out of scope.
///
/// The quickstart uses one to hold a throwaway PKI so that it needs no provisioning step. A real
/// application keeps its PKI in a protected, backed-up location instead.
class TemporaryDirectory
{
public:
  explicit TemporaryDirectory(std::string_view prefix);
  ~TemporaryDirectory();

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
  TemporaryDirectory(TemporaryDirectory&&) = delete;
  TemporaryDirectory& operator=(TemporaryDirectory&&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept
  {
    return mPath;
  }

private:
  std::filesystem::path mPath;
};

}  // namespace examples

#endif  // UASDK_EXAMPLE_SUPPORT_H
