// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIAGNOSTIC_COLLECTOR_H
#define UA_DIAGNOSTIC_COLLECTOR_H

#include "ua_diagnostic_bits.h"
#include "ua_diagnostic_security_context.h"
#include "ua_error_detail.h"
#include "ua_string_table_builder.h"

#include "ua_diagnostic_info.h"
#include "ua_response_header.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

namespace ua::server
{

/// Collects service-level error detail during service execution and serializes
/// it (along with per-item details sourced from the response's result
/// StatusCodes) to OPC UA DiagnosticInfo + string table at response time.
///
/// Created from the client's RequestHeader::return_diagnostics() bitmask and
/// the session's security context. When the effective bitmask is 0, all
/// methods are no-ops (zero overhead).
///
/// This type is internal to the service core. Namespace implementations and
/// user code never see it - they work with ErrorDetail on Result<T> /
/// StatusCode.
class DiagnosticCollector
{
public:
  /// Create from the client's returnDiagnostics bitmask and security context.
  /// The effective bitmask is the intersection of the client's request,
  /// the server's policy, and the security gates.
  DiagnosticCollector(uint32_t clientReturnDiagnostics, const DiagnosticSecurityContext& security);

  /// Create with no security gating (for testing).
  explicit DiagnosticCollector(uint32_t returnDiagnostics);

  /// True if the client requested any operation-level diagnostics and the
  /// security context permits it.
  bool wants_operation_diagnostics() const noexcept;

  /// True if the client requested any service-level diagnostics and the
  /// security context permits it.
  bool wants_service_diagnostics() const noexcept;

  /// True if pre-auth StatusCode masking should be applied to the response.
  bool should_mask_pre_auth_errors() const noexcept;

  /// The effective returnDiagnostics bitmask after security gating.
  uint32_t effective_return_diagnostics() const noexcept;

  // --- Collection ---

  /// Set the service-level diagnostic (for ResponseHeader.serviceDiagnostics).
  /// The detail is sourced from `status.shared_detail()`. No-op if the client
  /// didn't request service-level diagnostics or the status has no detail.
  void set_service_detail(StatusCode status);

  /// Add a per-item diagnostic at the given index.
  /// No-op if the client didn't request operation-level diagnostics.
  ///
  /// Transitional API: prefer attaching detail to the per-result StatusCode
  /// (which `apply_to(..., itemStatus, ...)` will walk). Use this only when
  /// the detail is independently produced (e.g. service-side authorization
  /// rejection where the per-item result holds only a bare Status).
  void add_item_detail(size_t index, shared_ptr<const ua::ErrorDetail> detail);

  /// Add a diagnostic beneath item `index`, against operation `operation` of that item.
  ///
  /// A few services answer one request slot with a *vector* of per-operation StatusCodes -
  /// HistoryUpdate's `operationResults` is the case this exists for - and the spec requires the
  /// matching DiagnosticInfo to sit in that result's own array rather than in the response's
  /// top-level one, where there is no slot for it. No-op if the client didn't request
  /// operation-level diagnostics.
  void add_operation_detail(size_t index, size_t operation, shared_ptr<const ua::ErrorDetail> detail);

  // --- Serialization ---

  /// Apply collected service-level diagnostic to the response.
  /// Use this for service-fault paths (no per-item results).
  void apply_to(ua::ResponseHeader& header) const;

  /// Apply collected diagnostics to the response (per-item details registered
  /// via `add_item_detail`).
  void apply_to(
    ua::ResponseHeader& header, ua::Array<ua::DiagnosticInfo>& itemDiagnostics, size_t resultCount) const;

  /// As the overload above, and additionally serialize the per-operation details registered
  /// through @ref add_operation_detail.
  ///
  /// `operationDiagnosticsFor(index)` is asked for the DiagnosticInfo array belonging to result
  /// `index` - `HistoryUpdateResult::diagnostic_infos()`, say - and may return nullptr for a
  /// result that has none. The array is sized to `operationCountFor(index)` before it is filled,
  /// so it stays parallel to that result's own operation results. One string table backs the
  /// service, item and operation levels alike, which is why this cannot be a second pass.
  void apply_to(ua::ResponseHeader& header, ua::Array<ua::DiagnosticInfo>& itemDiagnostics,
    size_t resultCount, const std::function<ua::Array<ua::DiagnosticInfo>*(size_t)>& operationDiagnosticsFor,
    const std::function<size_t(size_t)>& operationCountFor) const;

  /// Apply collected diagnostics to the response (per-item details sourced
  /// from per-result StatusCodes). Use when the per-result StatusCode carries
  /// the ErrorDetail directly.
  void apply_to(ua::ResponseHeader& header, std::function<StatusCode(size_t)> itemStatus, size_t resultCount,
    ua::Array<ua::DiagnosticInfo>& itemDiagnostics) const;

  /// Build DataChangeNotification diagnostics using each MonitoredItem's sticky returnDiagnostics mask.
  /// The collector is constructed with every diagnostic bit plus the current Session security context;
  /// each item mask is intersected with that permitted mask. The output stays empty unless at least one
  /// item has both requested operation-level diagnostics and supplied a renderable ErrorDetail. All
  /// emitted DiagnosticInfos share @p stringTable, preserving their response-header index domain.
  void apply_to_notification_items(ua::Array<ua::String>& stringTable,
    std::function<StatusCode(size_t)> itemStatus, std::function<uint32_t(size_t)> itemReturnDiagnostics,
    size_t itemCount, ua::Array<ua::DiagnosticInfo>& itemDiagnostics) const;

private:
  ua::DiagnosticInfo convert(
    const ua::ErrorDetail& detail, uint32_t levelBits, StringTableBuilder& table) const;

  uint32_t mReturnDiagnostics = 0;
  bool mMaskPreAuthErrors = false;

  shared_ptr<const ua::ErrorDetail> mServiceDetail;
  std::unordered_map<size_t, shared_ptr<const ua::ErrorDetail>> mItemDetails;
  // item index -> operation index -> detail. Sparse: only the operations that produced one.
  std::unordered_map<size_t, std::unordered_map<size_t, shared_ptr<const ua::ErrorDetail>>> mOperationDetails;
};

}  // namespace ua::server

#endif  // !UA_DIAGNOSTIC_COLLECTOR_H
