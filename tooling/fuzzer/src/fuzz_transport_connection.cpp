// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fuzz_transport_connection.h"

#include <boost/asio/ip/tcp.hpp>

namespace opcua_fuzzer
{

FuzzTransportConnection::FuzzTransportConnection(std::shared_ptr<ua::TransportConnection> inner)
  : mInner{std::move(inner)}
{}

void FuzzTransportConnection::set_write_interceptor(WriteInterceptor interceptor)
{
  std::lock_guard lock(mMutex);
  mInterceptor = std::move(interceptor);
}

void FuzzTransportConnection::inject_bytes(std::vector<std::byte> buffer)
{
  mInner->async_write(std::move(buffer));
}

void FuzzTransportConnection::register_error_callback(ErrorCallback callback)
{
  mInner->register_error_callback(std::move(callback));
}

void FuzzTransportConnection::register_read_callback(ReadCompleteCallback callback)
{
  mInner->register_read_callback(std::move(callback));
}

void FuzzTransportConnection::register_write_callback(WriteCompleteCallback callback)
{
  mInner->register_write_callback(std::move(callback));
}

asio::ip::tcp::endpoint FuzzTransportConnection::get_local_endpoint() const
{
  return mInner->get_local_endpoint();
}

void FuzzTransportConnection::async_read(std::vector<std::byte>&& buffer, size_t offset)
{
  mInner->async_read(std::move(buffer), offset);
}

size_t FuzzTransportConnection::bytes_available_to_read() const
{
  return mInner->bytes_available_to_read();
}

ua::StatusCode FuzzTransportConnection::read(std::vector<std::byte>& buffer, size_t offset)
{
  return mInner->read(buffer, offset);
}

void FuzzTransportConnection::async_write(std::vector<std::byte>&& buffer)
{
  async_write(std::move(buffer), /*startsMessage*/ true);
}

void FuzzTransportConnection::async_write(std::vector<std::byte>&& buffer, bool startsMessage)
{
  WriteInterceptor interceptor;
  {
    std::lock_guard lock(mMutex);
    interceptor = mInterceptor;
  }

  // The message-start flag is passed through unchanged: the inner transport applies its send caps
  // per message, and the wrapper must not turn every mutated chunk into a message of its own.
  if (interceptor)
  {
    auto mutated = interceptor(std::move(buffer));
    mInner->async_write(std::move(mutated), startsMessage);
  }
  else
  {
    mInner->async_write(std::move(buffer), startsMessage);
  }
}

void FuzzTransportConnection::close_async(std::function<void(ua::VoidResult)> callback, CloseMode mode)
{
  mInner->close_async(std::move(callback), mode);
}

}  // namespace opcua_fuzzer
