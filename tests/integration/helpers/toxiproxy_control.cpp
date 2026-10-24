// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "toxiproxy_control.h"

#include "environment_variable.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <istream>
#include <sstream>
#include <string>

namespace ua::test_helpers
{

namespace
{

namespace asio = boost::asio;
using asio::ip::tcp;

/// Splits a `host:port` (or a `scheme://host:port`) into host and port. Returns false on a
/// malformed address. The scheme prefix, if present, is stripped.
bool split_host_port(std::string address, std::string& host, uint16_t& port)
{
  auto schemePos = address.find("://");
  if (schemePos != std::string::npos)
    address = address.substr(schemePos + 3);

  auto colonPos = address.rfind(':');
  if (colonPos == std::string::npos || colonPos + 1 >= address.size())
    return false;

  host = address.substr(0, colonPos);
  try
  {
    const int parsed = std::stoi(address.substr(colonPos + 1));
    if (parsed <= 0 || parsed > 65535)
      return false;
    port = static_cast<uint16_t>(parsed);
  }
  catch (...)
  {
    return false;
  }
  return true;
}

}  // namespace

std::string ToxiproxyControl::default_admin_url()
{
  if (auto fromEnvironment = read_environment_variable("TOXIPROXY_ADMIN"))
    return std::move(*fromEnvironment);
  return "http://127.0.0.1:8474";
}

ToxiproxyControl::ToxiproxyControl(std::string adminUrl)
{
  if (!split_host_port(adminUrl, mAdminHost, mAdminPort))
  {
    // Fall back to the documented default rather than throwing from a test helper ctor.
    mAdminHost = "127.0.0.1";
    mAdminPort = 8474;
  }
}

std::string ToxiproxyControl::toxic_type_string(ToxicType type)
{
  switch (type)
  {
  case ToxicType::Latency:
    return "latency";
  case ToxicType::Slicer:
    return "slicer";
  case ToxicType::ResetPeer:
    return "reset_peer";
  case ToxicType::Timeout:
    return "timeout";
  case ToxicType::Bandwidth:
    return "bandwidth";
  case ToxicType::SlowClose:
    return "slow_close";
  }
  return "latency";
}

std::string ToxiproxyControl::stream_string(Stream stream)
{
  return stream == Stream::Upstream ? "upstream" : "downstream";
}

std::optional<int> ToxiproxyControl::request(const std::string& method, const std::string& path,
  const std::string& body, std::chrono::milliseconds timeout, std::string* responseBody) const
{
  try
  {
    asio::io_context io;
    tcp::socket socket{io};
    asio::steady_timer deadline{io};

    bool timedOut = false;
    deadline.expires_after(timeout);
    deadline.async_wait(
      [&](const boost::system::error_code& ec)
      {
        if (!ec)
        {
          timedOut = true;
          boost::system::error_code ignore;
          socket.close(ignore);
        }
      });

    // Resolve + connect (synchronously, but bounded by the deadline closing the socket).
    tcp::resolver resolver{io};
    boost::system::error_code resolveEc;
    auto endpoints = resolver.resolve(mAdminHost, std::to_string(mAdminPort), resolveEc);
    if (resolveEc)
      return std::nullopt;

    boost::system::error_code operationEc = asio::error::would_block;
    asio::async_connect(socket,
      endpoints,
      [&](const boost::system::error_code& ec, const tcp::endpoint&) { operationEc = ec; });

    // Run the io_context until either the connect completes or the deadline fires.
    io.restart();
    while (operationEc == asio::error::would_block && !timedOut)
      io.run_one();
    if (operationEc || timedOut)
      return std::nullopt;

    // Build and send the request.
    std::ostringstream requestStream;
    requestStream << method << " " << path << " HTTP/1.1\r\n"
                  << "Host: " << mAdminHost << ":" << mAdminPort << "\r\n"
                  << "Content-Type: application/json\r\n"
                  << "Content-Length: " << body.size() << "\r\n"
                  << "Connection: close\r\n"
                  << "\r\n"
                  << body;
    const std::string requestText = requestStream.str();

    operationEc = asio::error::would_block;
    asio::async_write(socket,
      asio::buffer(requestText),
      [&](const boost::system::error_code& ec, std::size_t) { operationEc = ec; });
    io.restart();
    while (operationEc == asio::error::would_block && !timedOut)
      io.run_one();
    if (operationEc || timedOut)
      return std::nullopt;

    // Read the status line.
    asio::streambuf responseBuffer;
    operationEc = asio::error::would_block;
    asio::async_read_until(socket,
      responseBuffer,
      "\r\n",
      [&](const boost::system::error_code& ec, std::size_t) { operationEc = ec; });
    io.restart();
    while (operationEc == asio::error::would_block && !timedOut)
      io.run_one();
    if (operationEc || timedOut)
      return std::nullopt;

    std::istream responseStream{&responseBuffer};
    std::string httpVersion;
    int statusCode = 0;
    responseStream >> httpVersion >> statusCode;

    if (responseBody != nullptr)
    {
      // Drain the rest of the connection (server closes it: Connection: close). We do not
      // parse chunked encoding or honour Content-Length precisely - the admin API returns
      // small, non-chunked bodies and the caller only needs status codes for control flow.
      operationEc = asio::error::would_block;
      asio::async_read(socket,
        responseBuffer,
        asio::transfer_all(),
        [&](const boost::system::error_code& ec, std::size_t) { operationEc = ec; });
      io.restart();
      while (operationEc == asio::error::would_block && !timedOut)
        io.run_one();
      std::ostringstream bodyStream;
      bodyStream << &responseBuffer;
      *responseBody = bodyStream.str();
    }

    deadline.cancel();
    boost::system::error_code ignore;
    socket.shutdown(tcp::socket::shutdown_both, ignore);
    return statusCode;
  }
  catch (...)
  {
    return std::nullopt;
  }
}

bool ToxiproxyControl::reachable(std::chrono::milliseconds timeout) const
{
  auto status = request("GET", "/version", "", timeout, nullptr);
  return status.has_value() && *status == 200;
}

std::optional<ToxiproxyControl::Proxy> ToxiproxyControl::create_proxy(
  const std::string& name, const std::string& listenHostPort, const std::string& upstreamHostPort)
{
  std::ostringstream payload;
  payload << "{\"name\":\"" << name << "\",\"listen\":\"" << listenHostPort << "\",\"upstream\":\""
          << upstreamHostPort << "\",\"enabled\":true}";

  auto status = request("POST", "/proxies", payload.str(), std::chrono::milliseconds{3000}, nullptr);
  if (!status.has_value())
    return std::nullopt;
  // 201 Created on success; 409 Conflict means a stale proxy of the same name exists.
  if (*status == 409)
  {
    // Remove the stale proxy and retry once.
    (void)request("DELETE", "/proxies/" + name, "", std::chrono::milliseconds{3000}, nullptr);
    status = request("POST", "/proxies", payload.str(), std::chrono::milliseconds{3000}, nullptr);
    if (!status.has_value())
      return std::nullopt;
  }
  if (*status != 200 && *status != 201)
    return std::nullopt;

  return Proxy{this, name, listenHostPort};
}

// --- Proxy ---

ToxiproxyControl::Proxy::Proxy(ToxiproxyControl* control, std::string name, std::string listen)
  : mControl{control}, mName{std::move(name)}, mListen{std::move(listen)}
{}

ToxiproxyControl::Proxy::Proxy(Proxy&& other) noexcept
  : mControl{other.mControl}, mName{std::move(other.mName)}, mListen{std::move(other.mListen)}
{
  other.mControl = nullptr;
}

ToxiproxyControl::Proxy& ToxiproxyControl::Proxy::operator=(Proxy&& other) noexcept
{
  if (this != &other)
  {
    destroy();
    mControl = other.mControl;
    mName = std::move(other.mName);
    mListen = std::move(other.mListen);
    other.mControl = nullptr;
  }
  return *this;
}

ToxiproxyControl::Proxy::~Proxy()
{
  destroy();
}

bool ToxiproxyControl::Proxy::destroy()
{
  if (mControl == nullptr || mName.empty())
    return false;
  auto status =
    mControl->request("DELETE", "/proxies/" + mName, "", std::chrono::milliseconds{3000}, nullptr);
  mControl = nullptr;
  mName.clear();
  return status.has_value() && (*status == 204 || *status == 200);
}

bool ToxiproxyControl::Proxy::add_toxic(const std::string& toxicName, ToxicType type, Stream stream,
  const std::string& attributeKey, int64_t attributeValue, double toxicity)
{
  std::vector<std::pair<std::string, int64_t>> attributes;
  if (!attributeKey.empty())
    attributes.emplace_back(attributeKey, attributeValue);
  return add_toxic(toxicName, type, stream, attributes, toxicity);
}

bool ToxiproxyControl::Proxy::add_toxic(const std::string& toxicName, ToxicType type, Stream stream,
  const std::vector<std::pair<std::string, int64_t>>& attributes, double toxicity)
{
  if (mControl == nullptr || mName.empty())
    return false;

  std::ostringstream payload;
  payload << "{\"name\":\"" << toxicName << "\",\"type\":\"" << ToxiproxyControl::toxic_type_string(type)
          << "\",\"stream\":\"" << ToxiproxyControl::stream_string(stream) << "\",\"toxicity\":" << toxicity
          << ",\"attributes\":{";
  for (std::size_t i = 0; i < attributes.size(); ++i)
  {
    if (i != 0)
      payload << ",";
    payload << "\"" << attributes[i].first << "\":" << attributes[i].second;
  }
  payload << "}}";

  auto status = mControl->request(
    "POST", "/proxies/" + mName + "/toxics", payload.str(), std::chrono::milliseconds{3000}, nullptr);
  return status.has_value() && (*status == 200 || *status == 201);
}

bool ToxiproxyControl::Proxy::remove_toxic(const std::string& toxicName)
{
  if (mControl == nullptr || mName.empty())
    return false;
  auto status = mControl->request(
    "DELETE", "/proxies/" + mName + "/toxics/" + toxicName, "", std::chrono::milliseconds{3000}, nullptr);
  return status.has_value() && (*status == 204 || *status == 200);
}

}  // namespace ua::test_helpers
