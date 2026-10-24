// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_hostname.h"

#include "ua_x509_certificate.h"

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <cctype>
#include <ranges>

namespace ua::detail
{

namespace
{

std::string normalized_certificate_hostname(std::string_view hostname)
{
  std::string normalized{hostname};
  std::ranges::transform(normalized,
    normalized.begin(),
    [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  if (!normalized.empty() && normalized.back() == '.')
  {
    normalized.pop_back();
  }
  return normalized;
}

}  // namespace

bool certificate_matches_hostname(std::string_view endpointHostname, const X509Certificate& certificate)
{
  boost::system::error_code addressError;
  const auto endpointAddress = boost::asio::ip::make_address(endpointHostname, addressError);
  if (!addressError)
  {
    const auto certificateAddresses = certificate.san_ip_addresses();
    if (std::ranges::find(certificateAddresses, endpointAddress) != certificateAddresses.end())
    {
      return true;
    }

    const auto certificateNames = certificate.san_hostnames();
    return std::ranges::any_of(certificateNames,
      [&endpointAddress](const std::string& certificateName)
      {
        boost::system::error_code certificateAddressError;
        const auto certificateAddress =
          boost::asio::ip::make_address(certificateName, certificateAddressError);
        return !certificateAddressError && certificateAddress == endpointAddress;
      });
  }

  const std::string normalizedEndpoint = normalized_certificate_hostname(endpointHostname);
  // The subjectAltName only (OPC 10000-6 6.2.2 Table 43): a host name in the subject commonName is not
  // matched (RFC 6125 6.4.4).
  const auto certificateNames = certificate.san_hostnames();
  // OPC 10000-4 6.1.3 Host Name: the HostName used to connect "shall be the same as one of the HostNames
  // specified in the Certificate" - an address matches an address, a name a name; localhost is not this
  // host's name, and a loopback address is not localhost.
  return std::ranges::any_of(certificateNames,
    [&normalizedEndpoint](const std::string& certificateName)
    { return normalized_certificate_hostname(certificateName) == normalizedEndpoint; });
}

std::string certificate_hostname_summary(const X509Certificate& certificate)
{
  std::string summary;
  for (const auto& hostname : certificate.san_hostnames())
  {
    if (!summary.empty())
    {
      summary += ", ";
    }
    summary += hostname;
  }
  for (const auto& address : certificate.san_ip_addresses())
  {
    if (!summary.empty())
    {
      summary += ", ";
    }
    summary += address.to_string();
  }
  if (summary.empty())
  {
    summary = certificate.subject_common_name();
  }
  return summary;
}

}  // namespace ua::detail
