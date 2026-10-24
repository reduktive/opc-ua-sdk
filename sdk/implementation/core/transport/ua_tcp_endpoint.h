// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Value type identifying a TCP transport endpoint by IP address and port.
/// @ingroup transport

#ifndef UA_TCP_ENDPOINT_H
#define UA_TCP_ENDPOINT_H

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace ua
{

/// An immutable IPv4 or IPv6 transport endpoint: an IP address paired with a port.
///
/// Constructed through the static factory functions, which validate their inputs and
/// throw on malformed addresses; the default-constructed value is the IPv4 address
/// 0.0.0.0 on port 0. Instances are small, copyable value types with no shared
/// ownership, and are safe to use from any thread.
/// @ingroup transport
class TcpEndpoint
{
public:
  /// IP protocol family of an endpoint's address.
  enum class IpVersion
  {
    V4,  ///< 32-bit IPv4 address (4 bytes).
    V6  ///< 128-bit IPv6 address (16 bytes).
  };

  /// Constructs the unspecified endpoint 0.0.0.0:0 (IPv4).
  TcpEndpoint() = default;

  /// Builds an IPv4 endpoint from raw address bytes.
  ///
  /// @param addr Exactly 4 bytes in network (big-endian) order; copied into the endpoint.
  /// @param port TCP port number in host byte order.
  /// @return The constructed IPv4 endpoint.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p addr is not 4 bytes.
  /// @see v6, from_bytes
  static TcpEndpoint v4(std::span<const std::uint8_t> addr, std::uint16_t port);

  /// Builds an IPv6 endpoint from raw address bytes.
  ///
  /// @param addr Exactly 16 bytes in network (big-endian) order; copied into the endpoint.
  /// @param port TCP port number in host byte order.
  /// @return The constructed IPv6 endpoint.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p addr is not 16 bytes.
  /// @see v4, from_bytes
  static TcpEndpoint v6(std::span<const std::uint8_t> addr, std::uint16_t port);

  /// Builds an endpoint from raw address bytes, inferring the IP version from the length.
  ///
  /// A 4-byte span yields an IPv4 endpoint; a 16-byte span yields an IPv6 endpoint.
  ///
  /// @param addr 4 bytes (IPv4) or 16 bytes (IPv6) in network (big-endian) order.
  /// @param port TCP port number in host byte order.
  /// @return The constructed endpoint.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p addr is neither 4 nor 16 bytes.
  /// @see v4, v6
  static TcpEndpoint from_bytes(std::span<const std::uint8_t> addr, std::uint16_t port);

  /// Builds an endpoint by parsing a textual IP address and an explicit port.
  ///
  /// @param address Numeric IPv4 (e.g. "127.0.0.1") or IPv6 (e.g. "::1") address; not a hostname.
  /// @param port    TCP port number in host byte order.
  /// @return The constructed endpoint, with version inferred from @p address.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p address is not a valid IP literal.
  static TcpEndpoint from_string(std::string_view address, std::uint16_t port);

  /// Builds an endpoint by parsing a combined "address:port" string.
  ///
  /// IPv4 uses "host:port" (e.g. "127.0.0.1:4840"); IPv6 must be bracketed as
  /// "[host]:port" (e.g. "[::1]:4840") to disambiguate the colons. An unbracketed
  /// address containing more than one colon is rejected as ambiguous.
  ///
  /// @param endpoint Combined address and port; the address part must be a numeric IP literal,
  ///                 not a hostname.
  /// @return The constructed endpoint.
  /// @throws UaException with @ref Status::BadInvalidArgument if the port is missing or invalid,
  ///         the IPv6 closing bracket is absent, the form is ambiguous, or the address is not a
  ///         valid IP literal.
  static TcpEndpoint from_string(std::string_view endpoint);

  /// Returns the IP version of this endpoint's address.
  /// @return The IP version of this endpoint's address.
  [[nodiscard]] IpVersion version() const;

  /// Returns the TCP port number in host byte order.
  /// @return The TCP port number in host byte order.
  [[nodiscard]] std::uint16_t port() const;

  /// Returns the address bytes in network (big-endian) order.
  ///
  /// The span has 4 elements for an IPv4 endpoint and 16 for an IPv6 endpoint, and
  /// remains valid for the lifetime of this endpoint.
  ///
  /// @return A non-owning view over the stored address bytes.
  [[nodiscard]] std::span<const std::uint8_t> address() const;

  /// Compares two endpoints for equality of version, address, and port.
  /// @param a The first endpoint to compare.
  /// @param b The second endpoint to compare.
  /// @return true when @p a and @p b have the same version, address, and port; false otherwise.
  friend bool operator==(const TcpEndpoint& a, const TcpEndpoint& b) = default;

private:
  IpVersion mVersion{IpVersion::V4};
  std::array<std::uint8_t, 16> mAddr{};  // V4 stored in first 4 bytes
  std::uint16_t mPort{0};
};

}  // namespace ua

#endif  // !UA_TCP_ENDPOINT_H
