// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_EVENT_EMIT_H
#define UA_SERVER_EVENT_EMIT_H

#include "ua_server_observer.h"
#include "ua_callback_safety.h"

#include <memory>

namespace ua::server::detail
{

template<typename F>
void emit_event(const Logger& logger, const std::shared_ptr<ServerObserver>& handler, F&& f) noexcept
{
  if (!handler)
    return;
  ::ua::detail::invoke_user_callback(logger, std::forward<F>(f));
}

}  // namespace ua::server::detail

#endif  // !UA_SERVER_EVENT_EMIT_H
