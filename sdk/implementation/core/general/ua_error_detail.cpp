// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_error_detail.h"

#include "ua_to_string.h"

#include <fmt/format.h>

namespace ua
{

namespace
{

// Appends the formatted ErrorDetail to `out`.
// `indent` controls the indentation of continuation lines (detail, caused by).
// The first line (summary) is written without leading indent - the caller is
// responsible for positioning it (e.g. inline after "caused by: ").
void append_detail(std::string& out, const ErrorDetail& detail, int indent)
{
  std::string pad(numeric_cast<size_t>(indent), ' ');

  // Summary line: [Source] Code: Summary (StatusCode)
  if (!detail.source.empty())
  {
    out += fmt::format("[{}] ", detail.source);
  }
  if (!detail.code.empty())
  {
    out += detail.code;
    if (!detail.summary.empty())
    {
      out += ": ";
    }
  }
  out += detail.summary;

  const StatusCode innerStatus{detail.innerStatus};
  if (innerStatus.is_bad())
  {
    out += fmt::format(" ({})", to_string(innerStatus));
  }

  if (!detail.detail.empty())
  {
    out += fmt::format("\n{}detail: {}", pad, detail.detail);
  }

  // Structured facts for this layer, one per line (insertion order).
  for (const auto& fact : detail.context)
  {
    out += fmt::format("\n{}{} = {}", pad, fact.key, fact.value);
  }

  if (detail.cause)
  {
    out += fmt::format("\n{}caused by: ", pad);
    append_detail(out, *detail.cause, indent + 2);
  }
}

}  // namespace

std::string to_string(const ErrorDetail& detail, int indent)
{
  std::string result(numeric_cast<size_t>(indent), ' ');
  append_detail(result, detail, indent + 2);
  return result;
}

std::string describe(const StatusCode& status)
{
  const ErrorDetail* detail = status.detail();
  if (detail == nullptr)
  {
    return to_string(status);
  }

  // to_string(ErrorDetail) opens with the detail's OWN inner status, and prints it
  // only when that status is Bad. So when the inner status matches the carrying
  // one - the ordinary case, a detail built with .cause(status) - the code is
  // already in the first line and prefixing it here would print it twice.
  // When it does not match, or the detail carries no inner status at all, the code
  // the caller actually holds would otherwise be absent from the rendering, so name
  // it in front.
  if (StatusCode{detail->innerStatus}.value() == status.value())
  {
    return to_string(*detail);
  }
  return fmt::format("{}: {}", to_string(status), to_string(*detail));
}

}  // namespace ua
