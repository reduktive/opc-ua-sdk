// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Transport addressing value types: a server bind address and an endpoint URL.
/// @ingroup transport

#ifndef UA_TRANSPORT_ADDRESS_H
#define UA_TRANSPORT_ADDRESS_H

#include "ua_defines.h"

#include <string>

namespace ua::transport
{

/// A local address a transport binds to in order to accept connections.
///
/// Pairs the transport profile with the profile-specific address string the
/// transport listens on (for the default UA-TCP profile, an `opc.tcp://`
/// endpoint URL). A value type with no ownership or threading semantics.
/// @ingroup transport
struct BindAddress
{
  /// Transport profile the address is interpreted under; selects how @ref address is parsed.
  TransportProfileId transportProfileId{TransportProfileId::UaTcpUaScUaBinary};

  /// Profile-specific listen address (e.g. an `opc.tcp://` URL for the UA-TCP profile).
  std::string address;

  /// Compares two bind addresses for equality by profile and address string.
  ///
  /// @param a The left-hand bind address to compare.
  /// @param b The right-hand bind address to compare.
  /// @return `true` if both addresses have the same profile and address string; otherwise `false`.
  friend bool operator==(const BindAddress& a, const BindAddress& b) = default;
};

/// An OPC UA endpoint URL (e.g. `opc.tcp://host:4840/path`).
///
/// A thin value wrapper around the URL string that offers a minimal,
/// transport-agnostic format check. It does not parse or validate the URL
/// against any specific transport's grammar.
/// @ingroup transport
class EndpointUrl
{
public:
  /// Constructs an empty endpoint URL.
  EndpointUrl() = default;

  /// Constructs an endpoint URL wrapping the given string.
  ///
  /// @param url The endpoint URL; taken by value and moved into storage. Not validated.
  explicit EndpointUrl(std::string url) : mUrl(std::move(url))
  {}

  /// Returns the wrapped URL string.
  ///
  /// @return Reference to the URL, valid for the lifetime of this object.
  [[nodiscard]] const std::string& str() const
  {
    return mUrl;
  }

  /// Reports whether the URL has a plausible scheme-bearing shape.
  ///
  /// Performs a minimal, transport-agnostic check only: the URL is non-empty and
  /// contains a `://` separator. It does not validate the scheme, host, or path.
  ///
  /// @return `true` if the URL is non-empty and contains `://`; otherwise `false`.
  [[nodiscard]] bool has_basic_format() const
  {
    return !mUrl.empty() && (mUrl.find("://") != std::string::npos);
  }

private:
  std::string mUrl;
};

}  // namespace ua::transport

#endif  // !UA_TRANSPORT_ADDRESS_H
