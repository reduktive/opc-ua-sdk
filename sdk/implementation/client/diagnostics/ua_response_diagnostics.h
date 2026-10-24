// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Shared wire-crossing marker attachment for a received server @ref ua::ResponseHeader.
/// @ingroup client

#ifndef UA_RESPONSE_DIAGNOSTICS_H
#define UA_RESPONSE_DIAGNOSTICS_H

#include "ua_error_detail.h"
#include "ua_response_header.h"

#include <cstdint>
#include <memory>

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

/// Builds the always-on wire-crossing marker (CL-DIAG-005/008/009) for a received response.
///
/// Runs the @ref DiagnosticInfoDecoder over the header's `serviceDiagnostics` / `stringTable`, recording
/// the header's `serviceResult` as the marker's inner status. The returned chain is the synthetic marker
/// (`source = "client.tier0.session.decode_diagnostic"`) with the decoded server chain (SymbolicId-prefixed,
/// depth-capped) beneath it when the server sent a `DiagnosticInfo`; when it did not, the chain is just the
/// marker. The marker is added unconditionally so a bad `Result<T>` always records the tier-0 wire boundary,
/// even when the request was sent with `returnDiagnostics == 0`.
///
/// `noexcept`: a malformed server `DiagnosticInfo` (out-of-range string-table indexes, deep
/// `innerDiagnosticInfo`) must NEVER throw out of a wire funnel (process-abort class  -  the reverse-connect
/// no-throw-in-handler lesson). The decode is depth-capped and index-tolerant; the internal `catch (...)` is
/// a defensive backstop that still returns a bare marker so the wire boundary is recorded regardless.
///
/// @param header        The received response header (its `serviceResult` is recorded on the marker).
/// @param maxChainDepth  Cap on the decoded server chain below the marker (CL-DIAG-009); beyond it the
/// decoder
///                       appends a single `client.diagnostic.truncated` sentinel. Defaults to 32; the tier-1
///                       funnel passes the per-Connection `ClientDiagnosticPolicy.maxChainDepth`, while the
///                       tier-0 secure-channel / session callers (which hold no per-Connection policy) use
///                       the default.
/// @param namespaceTable The Session `NamespaceTable` snapshot used to map a decoded `NamespaceURI` to its
///                       `server.namespace.<uri>` / `server.unknown.<uri>` source (CL-DIAG-007). NULL (the
///                       default, and every tier-0 handshake caller with no table yet) records the raw URI.
/// @return A non-null marker `ErrorDetail`; its cause is the decoded server chain when one was present.
[[nodiscard]] std::shared_ptr<const ua::ErrorDetail> attach_wire_marker(const ua::ResponseHeader& header,
  std::uint32_t maxChainDepth = 32,
  std::shared_ptr<const ua::client::NamespaceTable> namespaceTable = {}) noexcept;

}  // namespace ua::client::detail

#endif  // !UA_RESPONSE_DIAGNOSTICS_H
