// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#ifndef UA_REVERSE_CONNECT_ADMISSION_H
#define UA_REVERSE_CONNECT_ADMISSION_H

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace ua
{
class ConnectionProtocol;
}

namespace ua::client::detail
{

/// One accepted connection whose ReverseHello/Hello/Acknowledge handshake has not completed. The listener's
/// pending list is the single source of truth for the admission counts (CL-RC-007): the per-address count is
/// a scan of at most `maxPendingHandshakes` entries, so no parallel map can drift from it.
struct PendingHandshake
{
  std::shared_ptr<ua::ConnectionProtocol> connection;
  std::string remoteAddress;
};

/// Whether a connection from @p address may join @p pending under the total bound @p maxTotal and the
/// per-address bound @p maxPerAddress (CL-RC-007). Pure, so it is tested without sockets.
[[nodiscard]] inline bool admit_pending_handshake(std::span<const PendingHandshake> pending,
  std::string_view address, uint32_t maxTotal, uint32_t maxPerAddress)
{
  if (pending.size() >= maxTotal)
  {
    return false;
  }
  const auto fromSameAddress = static_cast<std::size_t>(std::count_if(pending.begin(),
    pending.end(),
    [address](const PendingHandshake& handshake) { return handshake.remoteAddress == address; }));
  return fromSameAddress < maxPerAddress;
}

}  // namespace ua::client::detail

#endif  // UA_REVERSE_CONNECT_ADMISSION_H
