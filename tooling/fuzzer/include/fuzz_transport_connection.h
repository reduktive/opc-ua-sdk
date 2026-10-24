// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_TRANSPORT_CONNECTION_H
#define FUZZ_TRANSPORT_CONNECTION_H

#include <boost/asio/ip/tcp.hpp>

#include "ua_transport_connection.h"

#include <functional>
#include <mutex>

namespace opcua_fuzzer
{

/// Interceptor callback receives outgoing write bytes (mutable). May modify or replace them.
using WriteInterceptor = std::function<std::vector<std::byte>(std::vector<std::byte>)>;

/// TransportConnection decorator that delegates everything to an inner connection but
/// intercepts outgoing write bytes via a configurable callback. Used by Layer 2/3 harnesses
/// to mutate transport-level frames before they hit the wire.
class FuzzTransportConnection final : public ua::TransportConnection
{
public:
  explicit FuzzTransportConnection(std::shared_ptr<ua::TransportConnection> inner);

  void set_write_interceptor(WriteInterceptor interceptor);

  /// Inject arbitrary bytes directly into the connection (bypassing the inner connection's write path).
  /// The bytes are sent as-is via the inner connection's async_write.
  void inject_bytes(std::vector<std::byte> buffer);

  // --- Delegated methods ---
  void register_error_callback(ErrorCallback callback) override;
  void register_read_callback(ReadCompleteCallback callback) override;
  void register_write_callback(WriteCompleteCallback callback) override;
  asio::ip::tcp::endpoint get_local_endpoint() const override;
  void async_read(std::vector<std::byte>&& buffer, size_t offset = 0) override;
  size_t bytes_available_to_read() const override;
  ua::StatusCode read(std::vector<std::byte>& buffer, size_t offset = 0) override;
  void async_write(std::vector<std::byte>&& buffer) override;
  void async_write(std::vector<std::byte>&& buffer, bool startsMessage) override;
  void close_async(std::function<void(ua::VoidResult)> callback = {}, CloseMode mode = CloseMode::Immediate) override;

private:
  std::shared_ptr<ua::TransportConnection> mInner;
  std::mutex mMutex;
  WriteInterceptor mInterceptor;
};

}  // namespace opcua_fuzzer

#endif  // !FUZZ_TRANSPORT_CONNECTION_H
