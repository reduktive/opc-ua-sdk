// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "reconnect_observer.h"

#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_status.h"

#include <string>

namespace examples::reconnect
{

void await(examples::Queue<Notification>& notifications, Notification wanted, std::string_view what)
{
  if (!notifications.wait_for_value(wanted, outageBudget))
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
      ua::ErrorDetail::build("ExampleReconnectNotObserved", std::string{what}, "client.reconnect")}};
  }
}

}  // namespace examples::reconnect
