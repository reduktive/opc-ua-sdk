// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_response_diagnostics.h"

#include "ua_diagnostic_info_decoder.h"

#include <memory>
#include <utility>

namespace ua::client::detail
{

std::shared_ptr<const ua::ErrorDetail> attach_wire_marker(const ua::ResponseHeader& header,
  std::uint32_t maxChainDepth, std::shared_ptr<const ua::client::NamespaceTable> namespaceTable) noexcept
{
  try
  {
    // Single source of truth: the SAME decoder the tier-0 ServiceFault / session paths use, so the tier-1
    // general surface produces the identical marker -> server-chain shape (CL-DIAG-005/007/008/009). The
    // depth cap (CL-DIAG-009) is the per-Connection policy value on the tier-1 funnel path, default 32
    // elsewhere; the NamespaceTable (CL-DIAG-007) is passed by the post-activation callers that hold one.
    DiagnosticInfoDecoder decoder{};
    decoder.maxChainDepth = maxChainDepth;
    decoder.namespaceTable = std::move(namespaceTable);
    return decoder.decode(header.service_diagnostics(), header.string_table(), header.service_result());
  }
  catch (...)
  {
    // A malformed server DiagnosticInfo must never throw out of a wire funnel. Fall back to a bare marker so
    // the wire boundary is still recorded on the chain (mirrors the decoder's null-info marker shape).
    auto marker = std::make_shared<ua::ErrorDetail>();
    marker->source = "client.tier0.session.decode_diagnostic";
    marker->summary = "server diagnostics decoded at the wire boundary";
    marker->innerStatus = header.service_result().value();
    return marker;
  }
}

}  // namespace ua::client::detail
