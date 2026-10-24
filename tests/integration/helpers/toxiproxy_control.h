// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_TOXIPROXY_CONTROL_H
#define UA_TEST_TOXIPROXY_CONTROL_H

/// @file
/// @brief Test-only client for the toxiproxy admin API (network-fault injection).
///
/// Talks to a running toxiproxy instance (https://github.com/Shopify/toxiproxy) over its
/// HTTP admin API. Used by the `Chaos` integration tests to put a deliberately degraded
/// link in front of the server and prove the server recovers and leaks no resources.
///
/// The admin endpoint defaults to `http://127.0.0.1:8474` and is overridable via the
/// environment variable `TOXIPROXY_ADMIN`. The implementation issues minimal synchronous
/// HTTP/1.1 requests over a plain Boost.Asio TCP socket - no JSON parsing is required
/// because the caller pre-assigns the proxy listen address, so only HTTP status codes are
/// inspected.
///
/// This is test infrastructure under `tests/`; it must never be linked into the SDK.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ua::test_helpers
{

/// Reusable client for the toxiproxy admin API.
///
/// One instance owns the connection parameters (admin host/port). Proxies and toxics are
/// created/removed through member functions; a created proxy is represented by a movable
/// @ref Proxy RAII handle that deletes the proxy on destruction.
class ToxiproxyControl
{
public:
  /// One toxiproxy toxic kind exercised by the chaos tests.
  ///
  /// The string sent on the wire is the toxiproxy `type` field. `Latency` and `Slicer`
  /// degrade the link; `ResetPeer` and `Timeout` break it.
  enum class ToxicType
  {
    Latency,  ///< Adds latency (`attributes.latency` ms) to the stream.
    Slicer,  ///< Slices packets into fragments (`attributes.average_size` bytes).
    ResetPeer,  ///< Sends a TCP RST after `attributes.timeout` ms (0 = immediate).
    Timeout,  ///< Stops all data and closes after `attributes.timeout` ms (0 = never).
    Bandwidth,  ///< Limits throughput to `attributes.rate` KB/s.
    SlowClose,  ///< Delays the TCP FIN by `attributes.delay` ms on close.
  };

  /// Which direction of the proxied stream a toxic applies to.
  enum class Stream
  {
    Upstream,  ///< Client -> server direction.
    Downstream,  ///< Server -> client direction.
  };

  /// Constructs a control client.
  ///
  /// @param adminUrl Admin base URL (e.g. `http://127.0.0.1:8474`). Defaults to the value of
  ///                 the `TOXIPROXY_ADMIN` environment variable, or `http://127.0.0.1:8474`
  ///                 when that is unset.
  explicit ToxiproxyControl(std::string adminUrl = default_admin_url());

  /// Returns the admin base URL: `$TOXIPROXY_ADMIN` or `http://127.0.0.1:8474`.
  static std::string default_admin_url();

  /// Probes whether a toxiproxy admin API is reachable at the configured admin URL.
  ///
  /// Issues `GET /version` with a short connect/response timeout. A test asserts it and fails,
  /// naming the missing toxiproxy, in environments without Docker/toxiproxy.
  ///
  /// @param timeout Maximum time to wait for the probe to complete.
  /// @return `true` if the admin API answered `200 OK`; `false` otherwise.
  bool reachable(std::chrono::milliseconds timeout = std::chrono::milliseconds{1500}) const;

  /// RAII handle to a created proxy. Deletes the proxy on destruction (best-effort).
  class Proxy
  {
  public:
    Proxy() = default;
    Proxy(Proxy&& other) noexcept;
    Proxy& operator=(Proxy&& other) noexcept;
    Proxy(const Proxy&) = delete;
    Proxy& operator=(const Proxy&) = delete;
    ~Proxy();

    /// Adds a toxic to this proxy.
    ///
    /// @param toxicName  Unique name for the toxic within this proxy (used to remove it).
    /// @param type       The toxic kind to apply.
    /// @param stream     Direction the toxic affects.
    /// @param attributeKey Single integer attribute key for the toxic (e.g. "timeout",
    ///                     "latency", "average_size"); empty to send no attributes.
    /// @param attributeValue Value for @p attributeKey.
    /// @param toxicity   Probability [0,1] the toxic is applied per connection (1.0 = always).
    /// @return `true` on success (HTTP 200/201).
    bool add_toxic(const std::string& toxicName, ToxicType type, Stream stream,
      const std::string& attributeKey, int64_t attributeValue, double toxicity = 1.0);

    /// Adds a toxic with multiple integer attributes (e.g. the slicer's `average_size` +
    /// `delay`, which together force per-read fragmentation rather than kernel-coalesced
    /// slices). @return `true` on success (HTTP 200/201).
    bool add_toxic(const std::string& toxicName, ToxicType type, Stream stream,
      const std::vector<std::pair<std::string, int64_t>>& attributes, double toxicity = 1.0);

    /// Removes a previously added toxic by name. @return `true` on success (HTTP 204).
    bool remove_toxic(const std::string& toxicName);

    /// Deletes the proxy immediately (also done by the destructor). @return `true` on success.
    bool destroy();

    /// @return `true` if this handle owns a live proxy.
    bool valid() const
    {
      return mControl != nullptr && !mName.empty();
    }

    /// @return The `host:port` address the proxy listens on (what the client connects to).
    const std::string& listen_address() const
    {
      return mListen;
    }

  private:
    friend class ToxiproxyControl;
    Proxy(ToxiproxyControl* control, std::string name, std::string listen);

    ToxiproxyControl* mControl{nullptr};
    std::string mName;
    std::string mListen;
  };

  /// Creates a proxy that forwards @p listenHostPort -> @p upstreamHostPort.
  ///
  /// @param name             Unique proxy name.
  /// @param listenHostPort   Address the proxy listens on (the client connects here),
  ///                         e.g. `127.0.0.1:20000`. Must be a port published by the
  ///                         toxiproxy container so the in-process client can reach it.
  /// @param upstreamHostPort The real server `host:port` to forward to.
  /// @return A valid @ref Proxy on success, or `nullopt` on failure.
  std::optional<Proxy> create_proxy(
    const std::string& name, const std::string& listenHostPort, const std::string& upstreamHostPort);

private:
  // Issues a single HTTP/1.1 request to the admin API. Returns the numeric status code, or
  // nullopt on transport failure. @p responseBody (if non-null) receives the response body.
  std::optional<int> request(const std::string& method, const std::string& path, const std::string& body,
    std::chrono::milliseconds timeout, std::string* responseBody) const;

  static std::string toxic_type_string(ToxicType type);
  static std::string stream_string(Stream stream);

  std::string mAdminHost;
  uint16_t mAdminPort{8474};
};

}  // namespace ua::test_helpers

#endif  // UA_TEST_TOXIPROXY_CONTROL_H
