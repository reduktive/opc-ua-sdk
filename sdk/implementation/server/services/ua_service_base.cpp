// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_service_base.h"

#include "ua_server_session_info.h"

namespace ua::server
{

Logger logger_of(const weak_ptr<SessionInfo>& session)
{
  if (auto locked = session.lock())
  {
    return locked->logger();
  }
  return {};
}

}  // namespace ua::server
