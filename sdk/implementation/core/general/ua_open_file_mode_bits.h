// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal bit tests on the Mode argument of FileType Open (not public API).

#ifndef UA_OPEN_FILE_MODE_BITS_H
#define UA_OPEN_FILE_MODE_BITS_H

#include "ua_open_file_mode.h"

#include <cstdint>

namespace ua::detail
{

/// The Mode bit of @p bit (Part 20 4.2.2: the Mode argument of Open is a Byte of OpenFileMode bits).
constexpr std::uint8_t file_mode_bits(OpenFileMode bit)
{
  return static_cast<std::uint8_t>(bit);
}

/// The Mode bits of every listed OpenFileMode, combined.
template<typename... Bits>
constexpr std::uint8_t file_mode_bits(OpenFileMode first, Bits... rest)
{
  return static_cast<std::uint8_t>(file_mode_bits(first) | file_mode_bits(rest...));
}

/// Whether @p mode has @p bit set.
constexpr bool has_file_mode(std::uint8_t mode, OpenFileMode bit)
{
  return (mode & file_mode_bits(bit)) != 0;
}

/// The Mode bits above Append (4:7), which Part 20 4.2.2 reserves: "Shall always be zero".
constexpr std::uint8_t reservedFileModeBits = 0xF0;

}  // namespace ua::detail

#endif  // UA_OPEN_FILE_MODE_BITS_H
