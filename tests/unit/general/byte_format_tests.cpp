// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Locks the hex rendering of byte ranges, which names certificates on disk.
///
/// Whether `std::byte` is formattable at all varies by {fmt} release, and not
/// monotonically: 9.1 through 11.2 accept it, 12.2 does not, and 11.2 ships a formatter
/// where the earlier releases relied on a scoped-enumeration fallback. `ua_byte_format.h`
/// supplies the missing piece only where it is missing. These cases pin the OUTPUT rather
/// than the mechanism, so an upgrade that changes the rendering fails here instead of
/// silently orphaning every certificate in a file store, whose filename is the `{:X}` form
/// below (ua_certificate_store_files.cpp).

#include <gtest/gtest.h>

#include "fmt/format.h"
#include "fmt/ranges.h"

#include "ua_byte_format.h"
#include "ua_utilities.h"

#include <cstddef>
#include <string>
#include <vector>

namespace
{

/// Spans the interesting cases: a zero that must still occupy two digits, a value below
/// 0x10 that shows whether zero-padding is applied, and three values with the high bit set
/// that show whether the byte is widened as signed.
const std::vector<std::byte> bytes{std::byte{0x00},
  std::byte{0x01},
  std::byte{0x0a},
  std::byte{0x7f},
  std::byte{0x80},
  std::byte{0xab},
  std::byte{0xff}};

}  // namespace

TEST(ByteFormatTests, PaddedLowercaseHexSeparatedBySpaces)
{
  EXPECT_EQ(fmt::format("{:02x}", fmt::join(bytes, " ")), "00 01 0a 7f 80 ab ff");
}

TEST(ByteFormatTests, UnpaddedUppercaseHexNamesCertificateFiles)
{
  // The certificate file store derives "<thumbprint>.der" from exactly this expression, so
  // this string is a storage format, not a display choice.
  EXPECT_EQ(fmt::format("{:X}", fmt::join(bytes, "")), "01A7F80ABFF");
}

TEST(ByteFormatTests, PaddedUppercaseHexRunsTogether)
{
  EXPECT_EQ(fmt::format("{:02X}", fmt::join(bytes, "")), "00010A7F80ABFF");
}

TEST(ByteFormatTests, PaddedLowercaseHexRunsTogether)
{
  EXPECT_EQ(fmt::format("{:02x}", fmt::join(bytes, "")), "00010a7f80abff");
}

TEST(ByteFormatTests, BytesToHexStringMatchesTheSpaceSeparatedForm)
{
  EXPECT_EQ(ua::utils::bytes_to_hex_string(bytes), "00 01 0a 7f 80 ab ff");
}
