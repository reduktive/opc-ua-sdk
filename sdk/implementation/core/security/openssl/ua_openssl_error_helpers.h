// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OPENSSL_ERROR_HELPERS_H
#define UA_OPENSSL_ERROR_HELPERS_H

#include "ua_error_detail.h"

#include <openssl/err.h>

#include <array>
#include <memory>
#include <string>

namespace ua::detail
{

/// Drains the OpenSSL error queue into a semicolon-separated string.
/// Returns an empty string if the queue is empty.
inline std::string drain_openssl_errors()
{
  std::string result;
  unsigned long err{0};
  while ((err = ERR_get_error()) != 0)
  {
    std::array<char, 256> buf{};
    ERR_error_string_n(err, buf.data(), buf.size());
    if (!result.empty())
    {
      result += "; ";
    }
    result += buf.data();
  }
  return result;
}

/// Like make_error_detail but also captures the OpenSSL error queue into mDetail.
/// Use at sites where an OpenSSL API just failed and the error queue is likely populated.
inline std::unique_ptr<ErrorDetail> make_openssl_error_detail(
  std::string code, std::string summary, std::string source)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->source = std::move(source);
  d->detail = drain_openssl_errors();
  return d;
}

}  // namespace ua::detail

#endif  // !UA_OPENSSL_ERROR_HELPERS_H
