// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_log_sink_implementations.h"

#include "ua_log_format.h"

#include "fmt/format.h"

namespace ua
{

void ConsoleLogSink::log(const LogEntry& entry)
{
  fmt::print(stderr, "{}", detail::format_log_line(entry));
}

}  // namespace ua
