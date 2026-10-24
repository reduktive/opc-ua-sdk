// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side decoder that turns a received server @ref ua::DiagnosticInfo into an
///        @ref ua::ErrorDetail chain capped with a synthetic wire-crossing marker.
/// @ingroup client

#ifndef UA_DIAGNOSTIC_INFO_DECODER_H
#define UA_DIAGNOSTIC_INFO_DECODER_H

#include "ua_array.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_status_code.h"
#include "ua_string.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

/// Decodes a received server `DiagnosticInfo` into an `ErrorDetail` chain and always adds the
/// outermost wire-crossing marker. Readers see the marker
/// (`source = "client.tier0.session.decode_diagnostic"`) and know everything below it arrived over
/// the wire.
///
/// Implements the subset of OPC UA client design section 8.15.2 required by CL-DIAG-005/007/008/009: the
/// always-on wire-crossing marker, the `server.symbolic.` `SymbolicId` prefix, the `NamespaceURI` source
/// mapping (`server.namespace.<uri>` / `server.unknown.<uri>` via @ref namespaceTable, CL-DIAG-007), and
/// the depth cap (section 7.10.4). NOT yet implemented (no requirement in this set): the
/// malformed-DiagnosticInfo sentinel. The full `ClientDiagnosticPolicy` is not yet built; only the depth cap
/// is consumed.
struct DiagnosticInfoDecoder
{
  /// Maximum decoded chain levels before tail truncation (section 7.10.4 default of 32).
  std::size_t maxChainDepth = 32;

  /// The Session `NamespaceTable` snapshot used to map a decoded `NamespaceURI` to the `ErrorDetail`
  /// `source` (CL-DIAG-007): `server.namespace.<uri>` when the URI is in this snapshot, else
  /// `server.unknown.<uri>`. NULL (the default, and every handshake-time decode before the
  /// `NamespaceArray` has been read) records the raw resolved URI verbatim  -  the historical behaviour.
  std::shared_ptr<const NamespaceTable> namespaceTable;

  /// Decodes @p info into an `ErrorDetail` chain and adds the outermost wire-crossing marker. When
  /// @p info is null the returned chain is just the marker, carrying @p terminalCode as its bare
  /// inner status.
  ///
  /// @param info         Received service-wide diagnostic (may be null).
  /// @param stringTable  Response-header string table for index resolution.
  /// @param terminalCode The operation/service status that crossed the wire; recorded on the marker.
  /// @return A non-null marker `ErrorDetail`; its cause is the decoded server chain when present.
  std::shared_ptr<const ErrorDetail> decode(
    const DiagnosticInfo& info, const Array<String>& stringTable, StatusCode terminalCode) const;

  /// As @ref decode, for the @p operationIndex-th operation of a bulk response: records the index in
  /// the marker's context and uses @p operationStatus as the terminal code.
  std::shared_ptr<const ErrorDetail> decode_operation(const DiagnosticInfo& info,
    const Array<String>& stringTable, StatusCode operationStatus, std::uint32_t operationIndex) const;
};

}  // namespace ua::client::detail

#endif  // !UA_DIAGNOSTIC_INFO_DECODER_H
