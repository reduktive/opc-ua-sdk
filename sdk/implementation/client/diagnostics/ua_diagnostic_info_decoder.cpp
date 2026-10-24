// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_diagnostic_info_decoder.h"

#include "ua_diagnostic_to_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_table.h"

#include <string>
#include <string_view>
#include <utility>

namespace ua::client::detail
{

namespace
{

// Builds the synthetic wire-crossing marker whose cause is the decoded server chain (when present). When
// @p namespaceTable is present, a decoded NamespaceURI is mapped to a `server.namespace.<uri>` /
// `server.unknown.<uri>` source (CL-DIAG-007); otherwise the raw URI is recorded verbatim.
std::shared_ptr<ErrorDetail> build_marked_chain(const DiagnosticInfo& info, const Array<String>& stringTable,
  StatusCode terminalCode, std::size_t maxChainDepth,
  const std::shared_ptr<const NamespaceTable>& namespaceTable)
{
  auto marker = std::make_shared<ErrorDetail>();
  marker->source = "client.tier0.session.decode_diagnostic";
  marker->summary = "server diagnostics decoded at the wire boundary";
  marker->innerStatus = terminalCode.value();

  if (!info.is_null())
  {
    DiagnosticDecodeOptions options{};
    options.maxChainDepth = maxChainDepth;
    options.prefixSymbolicId = true;
    if (namespaceTable)
    {
      options.namespaceSourceTag = [namespaceTable](std::string_view uri)
      {
        return namespaceTable->source_tag_for_namespace_uri(uri);
      };
    }
    marker->cause = diagnostic_to_error_detail(info, stringTable, options);
  }

  return marker;
}

}  // namespace

std::shared_ptr<const ErrorDetail> DiagnosticInfoDecoder::decode(
  const DiagnosticInfo& info, const Array<String>& stringTable, StatusCode terminalCode) const
{
  return build_marked_chain(info, stringTable, terminalCode, maxChainDepth, namespaceTable);
}

std::shared_ptr<const ErrorDetail> DiagnosticInfoDecoder::decode_operation(const DiagnosticInfo& info,
  const Array<String>& stringTable, StatusCode operationStatus, std::uint32_t operationIndex) const
{
  auto marker = build_marked_chain(info, stringTable, operationStatus, maxChainDepth, namespaceTable);
  marker->context.push_back(
    NamedValue{std::string(ContextKeys::operationIndex.value()), std::to_string(operationIndex)});
  return marker;
}

}  // namespace ua::client::detail
