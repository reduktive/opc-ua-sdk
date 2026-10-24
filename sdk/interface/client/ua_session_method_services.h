// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA Method Service Set on a Session.
/// @ingroup client

#ifndef UA_SESSION_METHOD_SERVICES_H
#define UA_SESSION_METHOD_SERVICES_H

#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_result.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for OPC UA Method Service Set operations on a Session.
///
/// Provides the Call service, which invokes one or more Methods on the server.
/// Instances are vended by a @ref Session and hold only a weak reference to the
/// owning session's implementation; they do not extend its lifetime and become
/// inert once the session is gone. Copyable as a lightweight handle.
/// @ingroup client
class SessionMethodServices
{
public:
  /// Result of a Call service invocation: a @ref CallResponse, or an @ref ErrorDetail on failure.
  using CallResponseResult = ua::Result<ua::CallResponse>;
  /// Callback receiving the outcome of @ref call_async.
  using CallCallback = std::function<void(CallResponseResult)>;

  /// Invokes one or more Methods on the server via the Call service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. A per-Method status is
  /// carried in the response's results - a successful Result indicates only that
  /// the service request itself completed.
  ///
  /// @param request  The Call request listing the Methods to invoke. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the @ref CallResponse;
  ///                 on failure it carries an @ref ErrorDetail. This overload never throws.
  /// @see call_sync, try_call_sync
  void call_async(ua::CallRequest request, CallCallback callback) noexcept;

  /// Invokes one or more Methods on the server, blocking until complete.
  ///
  /// @param request The Call request listing the Methods to invoke. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see call_async, try_call_sync
  /// A Good subcode on the answer is not returned; try_call_sync() returns it.
  ua::CallResponse call_sync(ua::CallRequest request);

  /// Invokes one or more Methods on the server, blocking until complete.
  ///
  /// @param request The Call request listing the Methods to invoke. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see call_async, call_sync
  CallResponseResult try_call_sync(ua::CallRequest request) noexcept;

private:
  friend class Session;
  explicit SessionMethodServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_METHOD_SERVICES_H
