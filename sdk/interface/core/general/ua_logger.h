// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Category-scoped, level-filtered logging facade with deferred (lazy) value formatting.
/// @ingroup general

#ifndef UA_LOGGER_H
#define UA_LOGGER_H

#include "ua_log_entry.h"
#include "ua_log_sink.h"

#include "fmt/format.h"

#include <atomic>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>

namespace ua
{

/// Wraps a callable so its result is formatted only if the log entry is actually emitted.
///
/// Pairs with the @c fmt formatter specialization at the bottom of this header: when a
/// @c LogLazy is passed as a format argument, the wrapped callable @c F is invoked and its
/// result formatted only at the point @c fmt renders the message. Use it to defer expensive
/// stringification (for example serializing a large structure) so that cost is paid only when
/// the surrounding level is enabled.
///
/// @tparam F Callable invoked with no arguments; its return value must itself be formattable.
/// @note Construct via the @ref log_lazy factory, which decays @p F for you.
/// @see log_lazy
template<typename F>
class LogLazy
{
public:
  /// Stores @p func for later evaluation.
  ///
  /// @param func Callable taking no arguments, moved into the wrapper.
  explicit LogLazy(F func) : mFunc(std::move(func))
  {}

  /// Invokes the wrapped callable and returns its result.
  ///
  /// @return The value produced by the wrapped callable.
  auto evaluate() const
  {
    return mFunc();
  }

private:
  F mFunc;
};

/// Wraps a callable in a `LogLazy` whose result is formatted lazily.
///
/// @tparam F Callable type, deduced and decayed into the resulting `LogLazy`.
/// @param f Callable taking no arguments; invoked only when the log message is rendered.
/// @return A `LogLazy` bound to @p f.
/// @see LogLazy
template<typename F>
LogLazy<F> log_lazy(F&& f)
{
  return LogLazy<std::decay_t<F>>(std::forward<F>(f));
}

/// A category-scoped, level-filtered handle for emitting log entries.
///
/// A @c Logger holds a shared @ref LogSink, a shared atomic minimum @ref LogLevel, and a
/// category string. The per-level methods (@ref trace, @ref debug, @ref info, @ref warning,
/// @ref error, @ref critical) format their message with @c fmt and forward it to the sink only
/// when the level passes the @ref is_enabled filter, so a disabled level costs no formatting.
/// A default-constructed @c Logger has no sink and is a silent no-op for every call.
///
/// Copying a @c Logger shares the underlying sink and level; the level is read atomically, so an
/// instance may be used from multiple threads concurrently. The sink is responsible for its own
/// thread safety (see @ref LogSink::log).
/// @ingroup general
class Logger
{
public:
  /// Constructs a null logger whose every logging call is a no-op.
  Logger() = default;

  /// Constructs a logger bound to a sink, a shared level filter, and a category.
  ///
  /// @param sink     Destination for emitted entries; shared ownership is retained. If null, the
  ///                 logger behaves as a no-op.
  /// @param level    Shared atomic minimum level; entries below it are dropped. Mutating it through
  ///                 the shared pointer reconfigures every @c Logger sharing it. Must be non-null
  ///                 when @p sink is non-null.
  /// @param category Category tag attached to every entry this logger emits.
  Logger(std::shared_ptr<LogSink> sink, std::shared_ptr<std::atomic<LogLevel>> level, std::string category);

  /// Reports whether an entry at @p level would be emitted.
  ///
  /// @param level Level to test.
  /// @return @c true if a sink is bound and @p level is at or above the current minimum level;
  ///         @c false otherwise.
  /// @note Thread-safe; the minimum level is read with relaxed atomic ordering.
  [[nodiscard]] bool is_enabled(LogLevel level) const noexcept
  {
    if (!mSink)
    {
      return false;
    }
    return level >= mLevel->load(std::memory_order_relaxed);
  }

  /// Emits a Trace-level entry, formatting the message only if Trace is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Trace.
  template<typename... Args>
  void trace(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Trace))
      return;
    write({LogLevel::Trace, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  /// Emits a Debug-level entry, formatting the message only if Debug is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Debug.
  template<typename... Args>
  void debug(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Debug))
      return;
    write({LogLevel::Debug, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  /// Emits an Info-level entry, formatting the message only if Info is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Info.
  template<typename... Args>
  void info(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Info))
      return;
    write({LogLevel::Info, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  /// Emits a Warning-level entry, formatting the message only if Warning is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Warning.
  template<typename... Args>
  void warning(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Warning))
      return;
    write({LogLevel::Warning, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  /// Emits an Error-level entry, formatting the message only if Error is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Error.
  template<typename... Args>
  void error(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Error))
      return;
    write({LogLevel::Error, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  /// Emits a Critical-level entry, formatting the message only if Critical is enabled.
  ///
  /// @tparam Args Format-argument types deduced from @p args.
  /// @param fmt  Compile-checked @c fmt format string.
  /// @param args Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Critical.
  template<typename... Args>
  void critical(fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Critical))
      return;
    write({LogLevel::Critical, mCategory, fmt::format(fmt, std::forward<Args>(args)...), {}});
  }

  // Overloads with structured fields

  /// Emits a Trace-level entry with structured fields, formatting only if Trace is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Trace.
  template<typename... Args>
  void trace(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Trace))
      return;
    write({LogLevel::Trace, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Emits a Debug-level entry with structured fields, formatting only if Debug is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Debug.
  template<typename... Args>
  void debug(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Debug))
      return;
    write({LogLevel::Debug, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Emits an Info-level entry with structured fields, formatting only if Info is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Info.
  template<typename... Args>
  void info(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Info))
      return;
    write({LogLevel::Info, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Emits a Warning-level entry with structured fields, formatting only if Warning is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Warning.
  template<typename... Args>
  void warning(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Warning))
      return;
    write({LogLevel::Warning, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Emits an Error-level entry with structured fields, formatting only if Error is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Error.
  template<typename... Args>
  void error(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Error))
      return;
    write({LogLevel::Error, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Emits a Critical-level entry with structured fields, formatting only if Critical is enabled.
  ///
  /// @tparam Args   Format-argument types deduced from @p args.
  /// @param fields  Key/value pairs attached to the entry for structured sinks. The referenced
  ///                @ref LogField data must outlive the call.
  /// @param fmt     Compile-checked @c fmt format string.
  /// @param args    Format arguments; wrap costly values in @ref log_lazy to defer their formatting.
  /// @note No-op when @ref is_enabled returns @c false for @ref LogLevel::Critical.
  template<typename... Args>
  void critical(std::initializer_list<LogField> fields, fmt::format_string<Args...> fmt, Args&&... args) const
  {
    if (!is_enabled(LogLevel::Critical))
      return;
    write({LogLevel::Critical, mCategory, fmt::format(fmt, std::forward<Args>(args)...), fields});
  }

  /// Returns a copy of this logger that tags entries with a different category.
  ///
  /// @param category New category string for the returned logger.
  /// @return A logger sharing this one's sink and level filter but using @p category.
  Logger with_category(std::string category) const;

private:
  void write(LogEntry entry) const;

  std::shared_ptr<LogSink> mSink;
  std::shared_ptr<std::atomic<LogLevel>> mLevel;
  std::string mCategory;
};

}  // namespace ua

/// @cond  fmt integration glue - excluded from the API reference (doxygen cannot
///        resolve the external `fmt::formatter` primary template's scope).
/// @c fmt formatter specialization that renders a @ref ua::LogLazy by evaluating it on demand.
///
/// Inherits string-formatting options from @c fmt::formatter<std::string>. The wrapped callable is
/// invoked, and its result formatted, only when the surrounding message is actually rendered - i.e.
/// only for log levels that pass the @ref ua::Logger::is_enabled filter.
///
/// @tparam F Callable type wrapped by the @ref ua::LogLazy.
/// @see ua::log_lazy
template<typename F>
struct fmt::formatter<ua::LogLazy<F>> : fmt::formatter<std::string>
{
  /// Evaluates @p lazy and formats its result into @p ctx.
  ///
  /// @param lazy Lazy value whose wrapped callable is invoked.
  /// @param ctx  Format context to write into.
  /// @return The output iterator past the last written character.
  auto format(const ua::LogLazy<F>& lazy, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(fmt::format("{}", lazy.evaluate()), ctx);
  }
};

/// @endcond

#endif  // UA_LOGGER_H
