// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_DATA_ACCESS_READINGS_H
#define UASDK_EXAMPLE_DATA_ACCESS_READINGS_H

/// @file
/// @brief Rendering Data Access values, and watching one through a filter the SDK composed.

#include "example_queue.h"

#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_data_access.h"
#include "ua_data_change_filter.h"

#include <memory>
#include <string>

namespace examples::readings
{

/// Renders an AnalogItem's value the way a display would: the number, its range, and its units.
std::string describe(const ua::client::AnalogItemValue& reading);

/// Prints the Pump's state together with the name this server gives it.
void report_pump_state(ua::client::TwoStateDiscreteHandle& pump);

/// Creates a Subscription and monitors @p node through @p filter, appending values to @p values.
ua::client::Subscription watch_with_deadband(ua::client::Connection& connection, const ua::NodeId& node,
  ua::DataChangeFilter filter, std::shared_ptr<examples::Queue<double>> values);

}  // namespace examples::readings

#endif  // UASDK_EXAMPLE_DATA_ACCESS_READINGS_H
