// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVICE_H
#define UA_SERVICE_H

#include "ua_includes.h"
#include "ua_integer_id.h"
#include "ua_status_code.h"

namespace ua
{

namespace server
{

class Service
{
public:
  Service() = delete;
  Service(const Service&) = delete;
  Service(Service&&) = delete;
  Service& operator=(const Service&) = delete;
  Service& operator=(Service&&) = delete;

  virtual ~Service()
  {}

  /// The client's Cancel (OPC 10000-4 5.6.5): by default @ref abort with Bad_RequestCancelledByClient.
  virtual void cancel()
  {
    abort(StatusCode{Status::BadRequestCancelledByClient});
  }

  /// Stops the call: sets its `RequestInfo::cancelled`, answers the client now with @p reason where the
  /// service answers a Cancel at once, and drops the namespaces' later answers. @p reason is
  /// Bad_RequestCancelledByClient for a Cancel and Bad_SessionClosed when the Session ends (OPC
  /// 10000-4 5.6.2.1).
  virtual void abort(StatusCode reason) = 0;

  IntegerId request_handle() const
  {
    return mRequestHandle;
  }

protected:
  Service(IntegerId requestHandle) : mRequestHandle(requestHandle)
  {}

private:
  const IntegerId mRequestHandle;
};

}  // namespace server

}  // namespace ua

#endif  // !UA_SERVICE_H
