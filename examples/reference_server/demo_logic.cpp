// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "demo_model.h"

#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <cmath>
#include <limits>

namespace reduktive::reference
{

// Turns an incoming OPC UA DataValue into the application's native Setpoint value. Conversion is
// deliberately performed before the range check so a client receives BadTypeMismatch for a value
// of the wrong built-in type and BadOutOfRange only for an invalid Double.
ua::Result<double> try_validate_setpoint(const ua::DataValue& incoming, const ua::NodeId& setpointId) noexcept
{
  try
  {
    auto decoded = incoming.value().to<double>();
    if (!decoded.is_good())
    {
      return ua::StatusCode{ua::Status::BadTypeMismatch,
        ua::ErrorDetail::build("ReferenceSetpointTypeMismatch",
          "Setpoint accepts a scalar OPC UA Double",
          "reference_server.demo.setpoint")
          .context(ua::ContextKeys::nodeId, setpointId)
          .cause(decoded.status_code())};
    }
    if (!std::isfinite(decoded.value()) || decoded.value() < 0.0 || decoded.value() > 100.0)
    {
      return ua::StatusCode{ua::Status::BadOutOfRange,
        ua::ErrorDetail::build("ReferenceSetpointOutOfRange",
          "Setpoint must be between 0 and 100 inclusive",
          "reference_server.demo.setpoint")
          .context(ua::ContextKeys::nodeId, setpointId)
          .context(ua::ContextKeys::value, fmt::format("{}", decoded.value()))
          .context(ua::ContextKeys::min, "0")
          .context(ua::ContextKeys::max, "100")};
    }
    return decoded.value();
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

// Implements the complete arithmetic domain of the reference Divide Method. The two explicit
// guards avoid undefined or invalid integer division, while successful inputs produce the typed
// Int32 output expected by the generated Method signature.
ua::Result<std::int32_t> try_divide(
  std::int32_t numerator, std::int32_t divisor, const ua::NodeId& methodId) noexcept
{
  try
  {
    if (divisor == 0)
    {
      return ua::StatusCode{ua::Status::BadInvalidArgument,
        ua::ErrorDetail::build("ReferenceDivideByZero",
          "Divide rejected the request because the divisor was zero",
          "reference_server.demo.divide")
          .context(ua::ContextKeys::nodeId, methodId)
          .context(ua::ContextKeys::value, divisor)
          .context(ua::ContextKeys::errorMessage, "Supply a non-zero divisor")};
    }
    if (numerator == std::numeric_limits<std::int32_t>::min() && divisor == -1)
    {
      return ua::StatusCode{ua::Status::BadOutOfRange,
        ua::ErrorDetail::build("ReferenceDivideOverflow",
          "Divide rejected the request because its Int32 quotient would overflow",
          "reference_server.demo.divide")
          .context(ua::ContextKeys::nodeId, methodId)
          .context(ua::ContextKeys::value, numerator)
          .context(ua::ContextKeys::errorMessage, "Use operands whose quotient fits in Int32")};
    }
    return static_cast<std::int32_t>(numerator / divisor);
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

}  // namespace reduktive::reference
