// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_result.h"

#include <string>
#include <string_view>

namespace ua::server
{

/// Upper-case-hex-no-spaces normalisation per Part 18 4.4.3 L766-769:
///   "the thumbprint shall be encoded as a hexadecimal string with upper case
///    characters and without spaces."
///
/// Accepts any mixed-case hex string with arbitrary internal whitespace, colons or dashes and
/// canonicalises it to the spec-prescribed shape. Rejects non-hex characters with
/// Bad_InvalidArgument. Shared by the Thumbprint identity-mapping rule and the X.509 re-activation
/// compare, so both sides of every thumbprint comparison are in one form whatever an authenticator
/// stored.
Result<std::string> normalise_identity_thumbprint(std::string_view input);

}  // namespace ua::server
