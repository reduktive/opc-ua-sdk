// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief {fmt} formatter for `std::byte`, supplied only for the releases that lack one.
/// @ingroup general

#ifndef UA_BYTE_FORMAT_H
#define UA_BYTE_FORMAT_H

#include <cstddef>

#include "fmt/format.h"

// Whether `std::byte` can be formatted at all depends on the {fmt} release, and the
// answer is not monotonic. Measured against the header-only builds of each release:
//
//   9.1.0   works   - scoped enumerations fall back to their underlying type
//   10.2.1  works   - same fallback
//   11.0.0  works   - same fallback
//   11.2.0  works   - {fmt} ships its own formatter<std::byte>
//   12.2.0  BROKEN  - the fallback is gone and no formatter replaced it, so a
//                     `{:02x}` over a range of bytes fails its compile-time check
//
// So the specialisation below is supplied only from 12.0.0 on. Declaring it
// unconditionally would be a redefinition against 11.2 and, in 9.1, would displace the
// fallback that `fmt::join` relies on and break the build outright - both observed.
// Revisit the lower bound if a later 12.x restores the formatter.
#if FMT_VERSION >= 120000

/// Formats a `std::byte` as the integer it holds, so the ordinary integer presentation
/// types apply: `{:02x}` writes two lowercase hex digits and `{:02X}` two uppercase ones.
/// This reproduces exactly what the earlier releases produced through the enum fallback,
/// which matters because the same expression names certificates in the file store.
template<>
struct fmt::formatter<std::byte> : fmt::formatter<unsigned char>
{
  template<class FormatContext>
  auto format(std::byte value, FormatContext& ctx) const
  {
    return fmt::formatter<unsigned char>::format(std::to_integer<unsigned char>(value), ctx);
  }
};

#endif  // FMT_VERSION >= 120000

#endif  // UA_BYTE_FORMAT_H
