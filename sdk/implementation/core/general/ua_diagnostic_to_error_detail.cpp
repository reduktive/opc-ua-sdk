// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_diagnostic_to_error_detail.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_to_string.h"

#include <fmt/format.h>

namespace ua
{

namespace
{

std::string resolve_string(const Array<String>& table, const optional<int32_t>& idx)
{
  if (!idx.has_value())
  {
    return {};
  }
  auto i = *idx;
  if (i < 0 || numeric_cast<size_t>(i) >= table.size())
  {
    return fmt::format("<unknown:{}>", i);
  }
  return std::string{table[numeric_cast<size_t>(i)]};
}

// Counts the number of levels in the DiagnosticInfo chain starting at (and including) @p info.
std::size_t count_inner_levels(const DiagnosticInfo& info)
{
  std::size_t levels = 1;
  const DiagnosticInfo* cursor = &info;
  while (cursor->inner_diagnostic_info())
  {
    ++levels;
    cursor = cursor->inner_diagnostic_info().get();
  }
  return levels;
}

// The terminal sentinel inserted when the wire chain exceeds the configured depth cap. Code and source
// per requirement CL-DIAG-009 (the design specification:207/217, the
// traceability authority) and the integration matrix; note the design specification section 8.15.2 currently
// spells the code "TRUNCATED" and is the outlier to reconcile.
std::shared_ptr<ErrorDetail> make_truncation_sentinel(std::size_t omittedLevels)
{
  auto sentinel = std::make_shared<ErrorDetail>();
  sentinel->code = "CHAIN_TRUNCATED";
  sentinel->source = "client.diagnostic.truncated";
  sentinel->context.push_back(
    NamedValue{std::string(ContextKeys::omittedDepth.value()), std::to_string(omittedLevels)});
  return sentinel;
}

// Decodes one DiagnosticInfo layer at 1-based @p depth, recursing into the inner layer until the
// chain ends or @p depth reaches options.maxChainDepth (at which point the remainder is replaced by
// a single truncation sentinel).
std::shared_ptr<ErrorDetail> decode_layer(const DiagnosticInfo& info, const Array<String>& stringTable,
  const DiagnosticDecodeOptions& options, std::size_t depth)
{
  auto detail = std::make_shared<ErrorDetail>();

  auto symbolic = resolve_string(stringTable, info.symbolic_id());
  if (options.prefixSymbolicId && !symbolic.empty())
  {
    detail->code = "server.symbolic." + symbolic;
  }
  else
  {
    detail->code = std::move(symbolic);
  }
  // CL-DIAG-007 (section 8.15.2): a non-empty NamespaceURI becomes `server.namespace.<uri>` (known to the
  // Session NamespaceArray) or `server.unknown.<uri>` (literal) via the wired interface. With no interface (core-only
  // callers, or handshake-time decodes before the NamespaceArray is read) the raw resolved URI is recorded
  // verbatim.
  auto namespaceUri = resolve_string(stringTable, info.namespace_uri());
  if (options.namespaceSourceTag && !namespaceUri.empty())
  {
    detail->source = options.namespaceSourceTag(namespaceUri);
  }
  else
  {
    detail->source = std::move(namespaceUri);
  }
  detail->summary = resolve_string(stringTable, info.localized_text());

  const auto& additionalInfo = info.additional_info();
  if (additionalInfo.has_value())
  {
    // Marker-tagged JSON -> discrete context (+ extended prose); plain text -> opaque mDetail.
    ua::detail::parse_additional_info(*additionalInfo, *detail);
  }

  const auto& innerStatusCode = info.inner_status_code();
  if (innerStatusCode.has_value())
  {
    detail->innerStatus = innerStatusCode->value();
  }

  if (info.inner_diagnostic_info())
  {
    if (depth >= options.maxChainDepth)
    {
      detail->cause = make_truncation_sentinel(count_inner_levels(*info.inner_diagnostic_info()));
    }
    else
    {
      detail->cause = decode_layer(*info.inner_diagnostic_info(), stringTable, options, depth + 1);
    }
  }

  return detail;
}

}  // namespace

std::shared_ptr<ErrorDetail> diagnostic_to_error_detail(
  const DiagnosticInfo& info, const Array<String>& stringTable, const DiagnosticDecodeOptions& options)
{
  return decode_layer(info, stringTable, options, /*depth=*/1);
}

std::string format_diagnostic(const DiagnosticInfo& info, const Array<String>& stringTable, int indent)
{
  auto detail = diagnostic_to_error_detail(info, stringTable);
  return to_string(*detail, indent);
}

std::string format_service_diagnostics(const ResponseHeader& header, const Array<DiagnosticInfo>& itemDiags,
  size_t itemCount, std::function<StatusCode(size_t)> itemStatus)
{
  std::string out;

  // Service-level
  const auto& serviceStatus = header.service_result();
  out += "Service: ";
  out += to_string(serviceStatus);
  out += "\n";

  if (!header.service_diagnostics().is_null())
  {
    auto detail = diagnostic_to_error_detail(header.service_diagnostics(), header.string_table());
    if (detail)
    {
      out += "  ";
      out += to_string(*detail, 2);
      out += "\n";
    }
  }

  // Per-item
  for (size_t i = 0; i < itemCount; ++i)
  {
    out += fmt::format("Item[{}]: ", i);
    if (itemStatus)
    {
      out += to_string(itemStatus(i));
    }
    else
    {
      out += "(no status callback)";
    }
    out += "\n";

    if (i < itemDiags.size() && !itemDiags[i].is_null())
    {
      auto detail = diagnostic_to_error_detail(itemDiags[i], header.string_table());
      if (detail && !detail->code.empty())
      {
        out += "  ";
        out += to_string(*detail, 2);
        out += "\n";
      }
    }
  }

  return out;
}

}  // namespace ua
