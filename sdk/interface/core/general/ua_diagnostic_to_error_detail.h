// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side conversion and formatting of wire @ref ua::DiagnosticInfo into
///        @ref ua::ErrorDetail cause chains and human-readable diagnostic strings.
/// @ingroup general

#ifndef UA_DIAGNOSTIC_TO_ERROR_DETAIL_H
#define UA_DIAGNOSTIC_TO_ERROR_DETAIL_H

#include "ua_array.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_response_header.h"
#include "ua_string.h"

#include <cstddef>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

namespace ua
{

/// Policy applied while decoding a wire @ref DiagnosticInfo into an @ref ErrorDetail chain.
///
/// The defaults reproduce the historical behaviour (no depth cap, bare `SymbolicId` as the
/// code) so existing callers are byte-identical; the client-side `DiagnosticInfoDecoder`
/// tightens them per OPC UA client design section 8.15.2.
/// @ingroup general
struct DiagnosticDecodeOptions
{
  /// Maximum number of decoded chain levels before tail truncation. When the wire chain is
  /// longer, the level at the cap keeps a synthetic terminal @ref ErrorDetail
  /// (`code = "CHAIN_TRUNCATED"`, `source = "client.diagnostic.truncated"`, context `omitted_depth`)
  /// as its cause instead of the real remainder.
  ///
  /// Defaults to no cap, deliberately: this struct is `core`, which holds no policy. The client
  /// supplies the cap - @ref ua::client::ClientDiagnosticPolicy::maxChainDepth, default 32 - and
  /// that is the only value a caller sets. "No cap" is not unbounded either way: the input has
  /// already been through the wire decoder, which charges recursion for each nested
  /// `InnerDiagnosticInfo` against @ref ua::ExecutionLimits::decodeRecursionDepthLimit (100).
  /// @see ua::client::ClientDiagnosticPolicy::maxChainDepth
  std::size_t maxChainDepth = std::numeric_limits<std::size_t>::max();

  /// When true, a non-empty resolved `SymbolicId` is recorded as the code with the
  /// @c server.symbolic. prefix, flagging it as server-originated and avoiding collisions with
  /// client-side codes (section 8.15.2). Defaults to false (bare id).
  bool prefixSymbolicId = false;

  /// When set, maps a decoded (already string-table-resolved) `NamespaceURI` to the `ErrorDetail`
  /// `source` (CL-DIAG-007, section 8.15.2). The client wires this to
  /// `NamespaceTable::source_tag_for_namespace_uri`, producing `server.namespace.<uri>` for a URI known
  /// to the Session `NamespaceArray` or `server.unknown.<uri>` for one that is not. Invoked only for a
  /// non-empty URI. UNSET (the default, and every core-only caller) records the raw resolved URI verbatim
  ///  -  the historical behaviour, and the correct fallback when no namespace context exists yet (e.g.
  /// handshake-time diagnostics decoded before the `NamespaceArray` has been read).
  std::function<std::string(std::string_view uri)> namespaceSourceTag;
};

/// Converts a wire @ref DiagnosticInfo into an @ref ErrorDetail cause chain.
///
/// This is the client-side inverse of the server's `DiagnosticCollector::convert()`:
/// it reconstructs the nested cause chain from a received @ref DiagnosticInfo. String
/// table indices embedded in @p info are resolved against @p stringTable (the table
/// carried in the response's @ref ResponseHeader); out-of-range indices yield
/// placeholder strings of the form `"<unknown:42>"`. A null @p info
/// (@ref DiagnosticInfo::is_null) produces an empty @ref ErrorDetail.
///
/// @param info        Received diagnostic, with string-table indices to resolve.
/// @param stringTable String table from the response header used to resolve indices.
/// @param options     Decode policy (depth cap, SymbolicId prefix); defaults reproduce the
///                    historical behaviour.
/// @return A non-null @ref ErrorDetail; empty when @p info is null.
/// @ingroup general
std::shared_ptr<ErrorDetail> diagnostic_to_error_detail(
  const DiagnosticInfo& info, const Array<String>& stringTable, const DiagnosticDecodeOptions& options = {});

/// Formats a `DiagnosticInfo` as a human-readable string, resolving all string-table
/// indices.
///
/// The output matches the `to_string(ErrorDetail)` format, for example:
///
///     [source] Code: Summary (InnerStatus 0x...)
///       detail: additional info text
///       caused by: [inner.source] InnerCode: InnerSummary (...)
///
/// Intended for logging per-item diagnostics from service responses.
///
/// @param info        Diagnostic to format.
/// @param stringTable String table from the response header used to resolve indices.
/// @param indent      Number of indentation levels to prefix each line with; nested
///                    causes are indented one level deeper.
/// @return The formatted diagnostic text.
std::string format_diagnostic(const DiagnosticInfo& info, const Array<String>& stringTable, int indent = 0);

/// Formats a complete service-response diagnostic string covering both the service-level
/// fault and the per-item diagnostics.
///
/// The output combines the service-level status with one line per result item, for
/// example:
///
///     Service: Good
///     Item[0]: Good
///     Item[1]: BadNodeIdUnknown (0x80340000)
///       [DefaultNamespace] NodeNotFound: Node i=999999 does not exist ...
///     Item[2]: Good
///
/// Or, for a service-level fault:
///
///     Service: BadTooManyOperations (0x80100000)
///       [AttributeServiceSet] TooManyNodesToRead: Requested 2 nodes exceeds limit of 1
///
/// @param header    Response header from the service response (supplies the service-level
///                  status and the string table used to resolve diagnostic indices).
/// @param itemDiags Per-item `DiagnosticInfo` array; may be empty.
/// @param itemCount Number of result items to render.
/// @param itemStatus Optional callback returning the `StatusCode` for item `i`. When
///                  null, per-item status lines show only the diagnostic. Invoked
///                  synchronously, once per item, during this call.
/// @return The formatted multi-line service diagnostic text.
std::string format_service_diagnostics(const ResponseHeader& header, const Array<DiagnosticInfo>& itemDiags,
  size_t itemCount, std::function<StatusCode(size_t)> itemStatus = {});

}  // namespace ua

#endif  // !UA_DIAGNOSTIC_TO_ERROR_DETAIL_H
