// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_diagnostic_info_decoder.h"
#include "ua_error_detail.h"
#include "ua_namespace_table.h"
#include "ua_namespace_uri.h"
#include "ua_response_diagnostics.h"

#include <memory>
#include <string>
#include <utility>

using namespace ua;
using namespace ua::client::detail;

namespace
{
// Counts links in an ErrorDetail chain and returns the terminal link.
std::pair<size_t, const ErrorDetail*> walk_chain(const ErrorDetail* head)
{
  size_t depth = 0;
  const ErrorDetail* last = nullptr;
  for (const ErrorDetail* cur = head; cur != nullptr; cur = cur->cause.get())
  {
    ++depth;
    last = cur;
  }
  return {depth, last};
}

std::unique_ptr<DiagnosticInfo> build_deep_chain(int levels)
{
  std::unique_ptr<DiagnosticInfo> chain;
  for (int i = 0; i < levels; ++i)
  {
    auto node = std::make_unique<DiagnosticInfo>();
    node->symbolic_id() = 0;
    node->inner_diagnostic_info() = std::move(chain);
    chain = std::move(node);
  }
  return chain;
}
}  // namespace

// @verifies CL-DIAG-005
// client_design.md section 8.15.2: the wire-crossing marker (source "client.tier0.session.decode_diagnostic")
// is ALWAYS the outermost link, even when the server sends no DiagnosticInfo - the chain then ends at the
// marker carrying the terminal (operation) status as its bare inner status. A broken client omits the
// marker when there is no server DiagnosticInfo.
// @relation(CL-DIAG-005, scope=function)
TEST(DiagnosticInfoDecoder, MarkerAddedEvenWhenServerSendsNoDiagnostic)
{
  DiagnosticInfoDecoder decoder{};
  DiagnosticInfo none;  // null
  Array<String> table;

  auto chain = decoder.decode(none, table, StatusCode{Status::BadNodeIdUnknown});

  ASSERT_NE(chain, nullptr);
  EXPECT_EQ(chain->source, "client.tier0.session.decode_diagnostic");
  EXPECT_EQ(StatusCode{chain->innerStatus}, StatusCode{Status::BadNodeIdUnknown});
  EXPECT_EQ(chain->cause, nullptr);  // no server chain below the marker
}

// @verifies CL-DIAG-005
// When the server DOES send a DiagnosticInfo, the marker is the outermost link and the decoded server chain
// hangs below it. The server link carries the SymbolicId with the "server.symbolic." prefix (CL-DIAG-008 as
// applied by the decoder).
// @relation(CL-DIAG-005, scope=function)
TEST(DiagnosticInfoDecoder, MarkerWrapsDecodedServerChainWithPrefixedSymbolicId)
{
  Array<String> table;
  table.payload().emplace_back("BadSensorOutOfRange");  // 0

  DiagnosticInfo info;
  info.symbolic_id() = 0;

  DiagnosticInfoDecoder decoder{};
  auto chain = decoder.decode(info, table, StatusCode{Status::BadInternalError});

  ASSERT_NE(chain, nullptr);
  EXPECT_EQ(chain->source, "client.tier0.session.decode_diagnostic");  // outermost == marker
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->code, "server.symbolic.BadSensorOutOfRange");
}

namespace
{
// A NamespaceTable snapshot containing NS0 + @p localUri (at index 1), for the CL-DIAG-007 source mapping.
std::shared_ptr<const ua::client::NamespaceTable> namespace_table_with(const std::string& localUri)
{
  return ua::client::NamespaceTable::create(
    {std::string{ua::specNamespaceUri}, localUri}, std::nullopt, /*generation=*/1)
    .value();
}
}  // namespace

// @verifies CL-DIAG-007
// client_design.md section 8.15.2: a decoded NamespaceURI that is KNOWN to the Session NamespaceTable becomes
// the ErrorDetail source `server.namespace.<uri>`. A broken decoder records the raw URI (no prefix),
// colliding with client-side sources and losing the "server-originated namespace" signal.
// @relation(CL-DIAG-007, scope=function)
TEST(DiagnosticInfoDecoder, KnownNamespaceUriResolvesToServerNamespaceSource)
{
  Array<String> table;
  table.payload().emplace_back("http://example.com/factory");  // string-table index 0 == the NamespaceURI

  DiagnosticInfo info;
  info.namespace_uri() = 0;  // index into the response string table

  DiagnosticInfoDecoder decoder{};
  decoder.namespaceTable = namespace_table_with("http://example.com/factory");  // URI IS known
  auto chain = decoder.decode(info, table, StatusCode{Status::BadInternalError});

  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->source, "server.namespace.http://example.com/factory")
    << "a known NamespaceURI must be recorded with the server.namespace. prefix";
}

// @verifies CL-DIAG-007
// An UNKNOWN NamespaceURI (absent from the NamespaceTable) is recorded literally with the `server.unknown.`
// prefix so the URI survives the round-trip for diagnostic-bug reports.
// @relation(CL-DIAG-007, scope=function)
TEST(DiagnosticInfoDecoder, UnknownNamespaceUriRecordsServerUnknownSource)
{
  Array<String> table;
  table.payload().emplace_back("http://other.com/");  // index 0 == the NamespaceURI

  DiagnosticInfo info;
  info.namespace_uri() = 0;

  DiagnosticInfoDecoder decoder{};
  decoder.namespaceTable = namespace_table_with("http://example.com/factory");  // does NOT contain other.com
  auto chain = decoder.decode(info, table, StatusCode{Status::BadInternalError});

  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->source, "server.unknown.http://other.com/")
    << "an unknown NamespaceURI must be recorded literally with the server.unknown. prefix";
}

// @verifies CL-DIAG-007
// With NO NamespaceTable wired (e.g. a handshake-time decode before the NamespaceArray is read) the decoder
// records the raw resolved URI verbatim - the historical fallback, since no namespace context exists yet.
// @relation(CL-DIAG-007, scope=function)
TEST(DiagnosticInfoDecoder, NoNamespaceTableRecordsRawUri)
{
  Array<String> table;
  table.payload().emplace_back("http://example.com/factory");

  DiagnosticInfo info;
  info.namespace_uri() = 0;

  DiagnosticInfoDecoder decoder{};  // no namespaceTable wired
  auto chain = decoder.decode(info, table, StatusCode{Status::BadInternalError});

  ASSERT_NE(chain, nullptr);
  ASSERT_NE(chain->cause, nullptr);
  EXPECT_EQ(chain->cause->source, "http://example.com/factory")
    << "with no NamespaceTable the raw resolved URI is recorded verbatim (historical fallback)";
}

// @verifies CL-DIAG-009
// The decoder applies its depth cap to the server chain below the marker: a 20-level server chain with
// maxChainDepth 5 yields marker + 5 real links + 1 sentinel (depth 7), sentinel omitted_depth 15.
// @relation(CL-DIAG-009, scope=function)
TEST(DiagnosticInfoDecoder, DepthCapAppliedToServerChainBelowMarker)
{
  Array<String> table;
  table.payload().emplace_back("L");  // 0
  auto serverChain = build_deep_chain(20);

  DiagnosticInfoDecoder decoder{};
  decoder.maxChainDepth = 5;
  auto marked = decoder.decode(*serverChain, table, StatusCode{Status::BadInternalError});

  auto [depth, terminal] = walk_chain(marked.get());
  EXPECT_EQ(depth, 7u);  // marker(1) + 5 server + sentinel(1)
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
  EXPECT_EQ(terminal->source, "client.diagnostic.truncated");
  ASSERT_EQ(terminal->context.size(), 1u);
  EXPECT_EQ(terminal->context[0].value, "15");  // 20 - 5
}

// @verifies CL-DIAG-005
// decode_operation records the operation index in the marker's context (for per-op bulk failures) and uses
// the operation status as the terminal code.
// @relation(CL-DIAG-005, scope=function)
TEST(DiagnosticInfoDecoder, DecodeOperationRecordsOperationIndex)
{
  DiagnosticInfoDecoder decoder{};
  DiagnosticInfo none;
  Array<String> table;

  auto chain =
    decoder.decode_operation(none, table, StatusCode{Status::BadNodeIdUnknown}, /*operationIndex=*/3);

  ASSERT_NE(chain, nullptr);
  EXPECT_EQ(chain->source, "client.tier0.session.decode_diagnostic");
  EXPECT_EQ(StatusCode{chain->innerStatus}, StatusCode{Status::BadNodeIdUnknown});
  ASSERT_EQ(chain->context.size(), 1u);
  EXPECT_EQ(chain->context[0].key, "operation.index");
  EXPECT_EQ(chain->context[0].value, "3");
}

// @verifies CL-DIAG-005
// Drives the production response-header wrapper, not just the decoder beneath it. A regression that ignores
// ResponseHeader::serviceResult would lose the wire-boundary status even though the decoder tests stay green.
// @relation(CL-DIAG-005, scope=function)
TEST(ResponseDiagnostics, AttachWireMarkerUsesResponseServiceResultWhenDiagnosticIsAbsent)
{
  ResponseHeader header;
  header.service_result() = StatusCode{Status::BadNodeIdUnknown};

  const auto marker = attach_wire_marker(header);

  ASSERT_NE(marker, nullptr);
  EXPECT_EQ(marker->source, "client.tier0.session.decode_diagnostic");
  EXPECT_EQ(StatusCode{marker->innerStatus}, StatusCode{Status::BadNodeIdUnknown});
  EXPECT_EQ(marker->cause, nullptr);
}

// @verifies CL-DIAG-007
// Proves that attach_wire_marker forwards both the response string table and the supplied Session namespace
// snapshot. Omitting either argument would leave the URI raw instead of classifying it as server-owned.
// @relation(CL-DIAG-007, scope=function)
TEST(ResponseDiagnostics, AttachWireMarkerForwardsStringAndNamespaceTables)
{
  ResponseHeader header;
  header.service_result() = StatusCode{Status::BadInternalError};
  header.string_table().payload().emplace_back("http://example.com/factory");
  header.service_diagnostics().namespace_uri() = 0;

  const auto marker = attach_wire_marker(header, 32, namespace_table_with("http://example.com/factory"));

  ASSERT_NE(marker, nullptr);
  ASSERT_NE(marker->cause, nullptr);
  EXPECT_EQ(marker->cause->source, "server.namespace.http://example.com/factory");
}

// @verifies CL-DIAG-009
// Proves that the connection policy's depth value crosses the response wrapper. With a cap of one, the
// second real server link must be replaced by the truncation sentinel.
// @relation(CL-DIAG-009, scope=function)
TEST(ResponseDiagnostics, AttachWireMarkerForwardsDepthCap)
{
  ResponseHeader header;
  header.service_result() = StatusCode{Status::BadInternalError};
  header.string_table().payload().emplace_back("Layer");
  header.service_diagnostics().symbolic_id() = 0;
  header.service_diagnostics().inner_diagnostic_info() = std::make_unique<DiagnosticInfo>();
  header.service_diagnostics().inner_diagnostic_info()->symbolic_id() = 0;

  const auto marker = attach_wire_marker(header, 1);

  ASSERT_NE(marker, nullptr);
  ASSERT_NE(marker->cause, nullptr);
  ASSERT_NE(marker->cause->cause, nullptr);
  EXPECT_EQ(marker->cause->cause->code, "CHAIN_TRUNCATED");
  EXPECT_EQ(marker->cause->cause->source, "client.diagnostic.truncated");
}
