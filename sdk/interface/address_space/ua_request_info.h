// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REQUEST_INFO_H
#define UA_REQUEST_INFO_H

/// @file
/// @brief What every asynchronous Namespace member is told about the request it serves, and on whose
///        behalf the members that act for a Session are called.
/// @ingroup address_space

#include "ua_defines.h"
#include "ua_locale_id.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_string.h"

#include <atomic>
#include <chrono>
#include <optional>
#include <vector>

namespace ua
{

class AccessIdentity;

namespace detail
{

/// The cancellation flag of a default-constructed @ref RequestInfo "RequestInfo": one flag, never set, shared
/// by every such RequestInfo. It is held by a `shared_ptr` that owns nothing, so neither building it nor
/// copying it allocates or counts references.
/// @return The flag; never null.
inline const shared_ptr<const std::atomic_bool>& never_cancelled() noexcept
{
  static const std::atomic_bool flag{false};
  static const shared_ptr<const std::atomic_bool> pointer{shared_ptr<const std::atomic_bool>{}, &flag};
  return pointer;
}

}  // namespace detail

/// The request a call into a namespace serves: its deadlines, its cancellation flag and the Session's
/// locales.
///
/// Every asynchronous `Namespace` member takes one as its first argument, so every member, lookups and
/// monitoring included, can be cancelled and has a deadline. The struct is plain data: the address space
/// fills it from the request, and a namespace that answers inline can ignore it.
///
/// **Lifetime.** Passed by `const&` and valid only until the member returns. A namespace that answers
/// later copies the struct (it is cheap: two time points, a shared flag and the locale list) or the
/// fields it needs.
///
/// **The server's own calls** (sampling, rollbacks, the SDK's internal lookups) carry a `deadline` of
/// `time_point::max()`, no `answerBy`, a flag that is never set and no locales.
/// @ingroup address_space
struct RequestInfo
{
  /// The partial-results deadline: the time by which a namespace that can answer part of a batch should
  /// return what it has. Set only for services that can return partial results (Browse, HistoryRead);
  /// `nullopt` for Read, Write and Call, which answer every item or fail it.
  std::optional<std::chrono::steady_clock::time_point> answerBy;

  /// The hard deadline: the request's arrival plus its `timeoutHint` (OPC 10000-4 7.33). After it the service
  /// has answered the client with `Bad_Timeout`, so work still running is wasted. `time_point::max()` for
  /// the server's own calls and for a `timeoutHint` of 0; the server sets no maximum of its own.
  std::chrono::steady_clock::time_point deadline{std::chrono::steady_clock::time_point::max()};

  /// Set when the client cancelled the request or the Session ended. Never null. A namespace that runs
  /// long work polls it and stops early; it still completes the call, once, with one result per item.
  /// The default is one flag shared by every default-constructed RequestInfo and never set, so a
  /// default RequestInfo allocates nothing.
  shared_ptr<const std::atomic_bool> cancelled{detail::never_cancelled()};

  /// The Session's locales, most preferred first (OPC 10000-4 5.6.3). Empty for the server's own calls. A
  /// namespace that holds LocalizedText in several locales may use them to choose what to fetch; the
  /// service still selects the locale it returns.
  std::vector<LocaleId> locales;
};

/// On whose behalf a namespace member is called: the Session's committed identity and the Session facts
/// a value source or a method handler may need.
///
/// Passed as `const CallerInfo*` to `read_values_async`, `write_async`, `call_async` and
/// `create_monitoring_async`. **A null pointer is the server's own call** (an internal read, a
/// sampling read of a subscription with no Session, a write the SDK makes for itself), not an anonymous
/// client. Lookups, References and View membership take no caller: what a Node is and what it references
/// does not depend on who asks.
///
/// A namespace whose answers do not depend on the caller ignores it. One that does - a per-user source,
/// a gateway that impersonates the client's user upstream (OPC 10000-4 5.6.3.1) - answers from it, because
/// no later stage can: the value has left the namespace by then.
///
/// **Lifetime.** The pointer is valid until the member RETURNS: the address space passes on the pointer
/// it was given, which may be the application's own (an accessor's value forms take one), and does not
/// copy it. A namespace that answers later copies the struct, or the `identity` `shared_ptr`, before it
/// returns.
///
/// The Session's locales are in @ref RequestInfo::locales, not here.
/// @ingroup address_space
struct CallerInfo
{
  /// The Session's committed identity: its granted Roles, its user and its endpoint. Never null in a
  /// `CallerInfo` the SDK builds; the server's own calls pass no `CallerInfo` at all.
  shared_ptr<const AccessIdentity> identity;

  /// The NodeId of the calling Session.
  NodeId sessionId;

  /// The authenticated user's id as audit events report it (`ClientUserId`).
  String clientUserId;

  /// The security mode of the SecureChannel the Session is activated on.
  MessageSecurityMode channelSecurityMode{MessageSecurityMode::Invalid};
};

}  // namespace ua

#endif  // UA_REQUEST_INFO_H
