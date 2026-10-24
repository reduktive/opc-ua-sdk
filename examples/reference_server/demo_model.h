// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef REDUKTIVE_REFERENCE_DEMO_MODEL_H
#define REDUKTIVE_REFERENCE_DEMO_MODEL_H

#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_result.h"

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace ua::server
{
class Server;
}

namespace reduktive::reference
{

/// Namespace URI declared by the external reference-server NodeSet. The URI, rather than the
/// runtime namespace index assigned during import, is the stable identity shared with clients.
inline constexpr std::string_view demoNamespaceUri = "urn:reduktive:reference-server:demo";

/// Decodes a Setpoint write as an OPC UA Double and accepts only finite values in [0, 100].
/// Returns the decoded value on success. Type and range failures retain a structured ErrorDetail
/// identifying the Setpoint node and the rejected value; no exception escapes this function.
ua::Result<double> try_validate_setpoint(
  const ua::DataValue& incoming, const ua::NodeId& setpointId) noexcept;

/// Divides two Int32 operands after rejecting division by zero and the INT32_MIN / -1 overflow case.
/// Domain failures are returned as bad StatusCodes with a structured ErrorDetail that identifies
/// the Method and corrective action; no exception escapes this function.
ua::Result<std::int32_t> try_divide(
  std::int32_t numerator, std::int32_t divisor, const ua::NodeId& methodId) noexcept;

/// Registers the model namespace and its secure-access defaults, imports the external NodeSet,
/// attaches the checked-in generated Demo handle, and binds the live UptimeSeconds, Setpoint, and
/// Divide handlers. Returns the first failure with its ErrorDetail preserved; no exception escapes
/// this function.
ua::VoidResult try_configure_demo_model(
  ua::server::Server& server, const std::filesystem::path& modelPath, ua::Logger applicationLogger) noexcept;

}  // namespace reduktive::reference

#endif  // REDUKTIVE_REFERENCE_DEMO_MODEL_H
