// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "endpoints.h"

#include <boost/asio/ip/address.hpp>

#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace reduktive::reference
{
namespace
{
/// Extracts the host from a `host:port` listen address. Bracketed IPv6 literals are supported;
/// a malformed address is rejected before it can reach a certificate's subject alternative names.
std::string host_from_listen_address(std::string_view address)
{
  if (address.starts_with('['))
  {
    const auto closingBracket = address.find(']');
    if (closingBracket == std::string_view::npos)
    {
      throw std::invalid_argument{"an IPv6 --listen host must be enclosed in []"};
    }
    return std::string{address.substr(1, closingBracket - 1)};
  }
  const auto separator = address.rfind(':');
  if (separator == std::string_view::npos || separator == 0 || separator + 1 == address.size())
  {
    throw std::invalid_argument{"--listen must have the form host:port"};
  }
  return std::string{address.substr(0, separator)};
}

}  // namespace

CertificateProfile server_certificate_profile(std::string_view listenAddress)
{
  CertificateProfile profile;
  profile.commonName = "Reduktive Reference Server";
  profile.applicationUri = std::string{applicationUri};
  profile.dnsNames.push_back("localhost");
  profile.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));

  const std::string host = host_from_listen_address(listenAddress);
  boost::system::error_code addressError;
  const auto ipAddress = boost::asio::ip::make_address(host, addressError);
  if (addressError)
  {
    if (std::ranges::find(profile.dnsNames, host) == profile.dnsNames.end())
    {
      profile.dnsNames.push_back(host);
    }
  }
  else if (std::ranges::find(profile.ipAddresses, ipAddress) == profile.ipAddresses.end())
  {
    profile.ipAddresses.push_back(ipAddress);
  }
  return profile;
}

ua::server::ListenerHandle add_secure_endpoint(ua::server::Server& server, const std::string& listenAddress)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  bind.address = listenAddress;
  const ua::server::ListenerHandle listener = server.listen_sync(std::move(bind), {});

  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256-SignAndEncrypt";
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  server.add_endpoint(listener, std::move(endpoint));
  return listener;
}

}  // namespace reduktive::reference
