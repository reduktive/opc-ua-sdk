// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_diagnostic_bits.h"
#include "ua_diagnostic_collector.h"
#include "ua_diagnostic_to_error_detail.h"
#include "ua_error_detail.h"
#include "ua_string_table_builder.h"

using namespace ua;
using namespace ua::server;

// --- diagnostic_to_error_detail ---

// @verifies CL-DIAG-010
// client_design.md 8.15.4: the decoder constructs every link defensively - absent DiagnosticInfo fields
// yield empty strings and a Good inner status, never a crash or a dereferenced empty optional. A wholly
// empty DiagnosticInfo therefore decodes to a non-null ErrorDetail with all fields empty.
// @relation(CL-DIAG-010, scope=function)
TEST(DiagnosticToErrorDetail, EmptyDiagnosticInfoProducesEmptyDetail)
{
  DiagnosticInfo info;
  Array<String> table;

  auto detail = diagnostic_to_error_detail(info, table);

  ASSERT_NE(detail, nullptr);
  EXPECT_TRUE(detail->code.empty());
  EXPECT_TRUE(detail->source.empty());
  EXPECT_TRUE(detail->summary.empty());
  EXPECT_TRUE(detail->detail.empty());
  EXPECT_TRUE(StatusCode{detail->innerStatus}.is_good());
  EXPECT_EQ(detail->cause, nullptr);
}

TEST(DiagnosticToErrorDetail, ResolvesAllStringTableFields)
{
  // Build a string table with known entries.
  Array<String> table;
  table.payload().emplace_back("TestCode");  // 0
  table.payload().emplace_back("TestSource");  // 1
  table.payload().emplace_back("Test summary");  // 2

  DiagnosticInfo info;
  info.symbolic_id() = 0;
  info.namespace_uri() = 1;
  info.localized_text() = 2;
  info.additional_info() = "Extended details here";
  info.inner_status_code() = StatusCode{Status::BadTimeout};

  auto detail = diagnostic_to_error_detail(info, table);

  EXPECT_EQ(detail->code, "TestCode");
  EXPECT_EQ(detail->source, "TestSource");
  EXPECT_EQ(detail->summary, "Test summary");
  EXPECT_EQ(detail->detail, "Extended details here");
  EXPECT_EQ(StatusCode{detail->innerStatus}, StatusCode{Status::BadTimeout});
  EXPECT_EQ(detail->cause, nullptr);
}

// @verifies CL-DIAG-010
// client_design.md 8.15.4: a DiagnosticInfo carrying only a subset of fields (here only SymbolicId) must
// decode with the present field resolved and every absent field defaulted to empty / Good - no crash.
// @relation(CL-DIAG-010, scope=function)
TEST(DiagnosticToErrorDetail, PartialFieldsOnlySymbolicId)
{
  Array<String> table;
  table.payload().emplace_back("OnlyCode");

  DiagnosticInfo info;
  info.symbolic_id() = 0;

  auto detail = diagnostic_to_error_detail(info, table);

  EXPECT_EQ(detail->code, "OnlyCode");
  EXPECT_TRUE(detail->source.empty());
  EXPECT_TRUE(detail->summary.empty());
  EXPECT_TRUE(detail->detail.empty());
  EXPECT_TRUE(StatusCode{detail->innerStatus}.is_good());
}

TEST(DiagnosticToErrorDetail, OutOfRangeIndexProducesPlaceholder)
{
  Array<String> table;
  table.payload().emplace_back("only_entry");  // index 0

  DiagnosticInfo info;
  info.symbolic_id() = 999;
  info.namespace_uri() = -1;

  auto detail = diagnostic_to_error_detail(info, table);

  EXPECT_EQ(detail->code, "<unknown:999>");
  EXPECT_EQ(detail->source, "<unknown:-1>");
}

// @verifies CL-DIAG-006
// client_design.md 8.15.2: each DiagnosticInfo layer becomes exactly one ErrorDetail link, chained via
// mCause following InnerDiagnosticInfo, and each link's innerStatus carries that layer's InnerStatusCode.
// A 3-layer wire chain (outer -> inner -> leaf) therefore decodes to a 3-link ErrorDetail chain, with the
// terminal (leaf) link's mCause null and its innerStatus holding the deepest InnerStatusCode.
// NOTE (impl-vs-doc, flagged): the doc phrases the deepest InnerStatusCode as a "bare status *cause*"; the
// implementation instead records it on the terminal link's innerStatus (mCause == nullptr). The
// information is preserved; only the structural placement differs.
// @relation(CL-DIAG-006, scope=function)
TEST(DiagnosticToErrorDetail, NestedCauseChain)
{
  Array<String> table;
  table.payload().emplace_back("OuterCode");  // 0
  table.payload().emplace_back("OuterSummary");  // 1
  table.payload().emplace_back("InnerCode");  // 2
  table.payload().emplace_back("InnerSummary");  // 3
  table.payload().emplace_back("LeafCode");  // 4
  table.payload().emplace_back("LeafSummary");  // 5

  // Build 3-level chain: outer -> inner -> leaf.
  auto leaf = std::make_unique<DiagnosticInfo>();
  leaf->symbolic_id() = 4;
  leaf->localized_text() = 5;
  leaf->inner_status_code() = StatusCode{Status::BadOutOfMemory};

  auto inner = std::make_unique<DiagnosticInfo>();
  inner->symbolic_id() = 2;
  inner->localized_text() = 3;
  inner->inner_status_code() = StatusCode{Status::BadInternalError};
  inner->inner_diagnostic_info() = std::move(leaf);

  DiagnosticInfo outer;
  outer.symbolic_id() = 0;
  outer.localized_text() = 1;
  outer.inner_status_code() = StatusCode{Status::BadTimeout};
  outer.inner_diagnostic_info() = std::move(inner);

  auto detail = diagnostic_to_error_detail(outer, table);

  // Outer level.
  EXPECT_EQ(detail->code, "OuterCode");
  EXPECT_EQ(detail->summary, "OuterSummary");
  EXPECT_EQ(StatusCode{detail->innerStatus}, StatusCode{Status::BadTimeout});
  ASSERT_NE(detail->cause, nullptr);

  // Inner level.
  auto& cause1 = *detail->cause;
  EXPECT_EQ(cause1.code, "InnerCode");
  EXPECT_EQ(cause1.summary, "InnerSummary");
  EXPECT_EQ(StatusCode{cause1.innerStatus}, StatusCode{Status::BadInternalError});
  ASSERT_NE(cause1.cause, nullptr);

  // Leaf level.
  auto& cause2 = *cause1.cause;
  EXPECT_EQ(cause2.code, "LeafCode");
  EXPECT_EQ(cause2.summary, "LeafSummary");
  EXPECT_EQ(StatusCode{cause2.innerStatus}, StatusCode{Status::BadOutOfMemory});
  EXPECT_EQ(cause2.cause, nullptr);
}

TEST(DiagnosticToErrorDetail, RoundTripThroughDiagnosticCollector)
{
  // Build a rich ErrorDetail with cause chain.
  auto innerDetail = std::make_shared<ErrorDetail>();
  innerDetail->code = "InnerError";
  innerDetail->summary = "Something broke internally";
  innerDetail->detail = "Stack trace or debug info";
  innerDetail->source = "TestComponent.Inner";
  innerDetail->innerStatus = StatusCode{Status::BadOutOfMemory}.value();

  auto originalDetail = std::make_shared<ErrorDetail>();
  originalDetail->code = "OuterError";
  originalDetail->summary = "Operation failed";
  originalDetail->detail = "Request ID 42 timed out after 30s";
  originalDetail->source = "TestComponent.Outer";
  originalDetail->innerStatus = StatusCode{Status::BadTimeout}.value();
  originalDetail->cause = innerDetail;

  // Forward path: ErrorDetail -> DiagnosticInfo + string table via DiagnosticCollector.
  DiagnosticCollector collector{0xFFFF};  // all bits enabled
  collector.set_service_detail(StatusCode{Status::BadTimeout, originalDetail});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  auto& diagInfo = header.service_diagnostics();
  ASSERT_TRUE(diagInfo.is_not_null());

  // Reverse path: DiagnosticInfo + string table -> ErrorDetail.
  auto recovered = diagnostic_to_error_detail(diagInfo, header.string_table());

  // Verify round-trip fidelity.
  EXPECT_EQ(recovered->code, originalDetail->code);
  EXPECT_EQ(recovered->summary, originalDetail->summary);
  EXPECT_EQ(recovered->detail, originalDetail->detail);
  EXPECT_EQ(recovered->source, originalDetail->source);
  EXPECT_EQ(recovered->innerStatus, originalDetail->innerStatus);

  // Verify cause chain.
  ASSERT_NE(recovered->cause, nullptr);
  EXPECT_EQ(recovered->cause->code, innerDetail->code);
  EXPECT_EQ(recovered->cause->summary, innerDetail->summary);
  EXPECT_EQ(recovered->cause->detail, innerDetail->detail);
  EXPECT_EQ(recovered->cause->source, innerDetail->source);
  EXPECT_EQ(recovered->cause->innerStatus, innerDetail->innerStatus);
  EXPECT_EQ(recovered->cause->cause, nullptr);
}

TEST(DiagnosticToErrorDetail, ContextRoundTripsThroughCollectorIncludingCauseChain)
{
  // Inner (cause) layer carries its own structured fact.
  auto inner = std::make_shared<ErrorDetail>();
  inner->code = "InnerError";
  inner->summary = "persist failed";
  inner->source = "server.namespace.factory_floor";
  inner->context.push_back(NamedValue{"node.id", "ns=2;i=5"});

  // Outer layer carries two facts and wraps the inner cause.
  auto outer = std::make_shared<ErrorDetail>();
  outer->code = "OuterError";
  outer->summary = "write rejected";
  outer->source = "server.services.write";
  outer->context.push_back(NamedValue{"operation.index", "0"});
  outer->context.push_back(NamedValue{"size.actual", "5000"});
  outer->cause = inner;

  DiagnosticCollector collector{0xFFFF};  // all bits, including AdditionalInfo
  collector.set_service_detail(StatusCode{Status::BadTimeout, outer});

  ResponseHeader header;
  collector.apply_to(header);

  auto recovered = diagnostic_to_error_detail(header.service_diagnostics(), header.string_table());

  // Outer layer's context survives, in order.
  ASSERT_EQ(recovered->context.size(), 2u);
  EXPECT_EQ(recovered->context[0].key, "operation.index");
  EXPECT_EQ(recovered->context[0].value, "0");
  EXPECT_EQ(recovered->context[1].key, "size.actual");
  EXPECT_EQ(recovered->context[1].value, "5000");

  // The cause layer's context survives independently (per-layer, not merged).
  ASSERT_NE(recovered->cause, nullptr);
  ASSERT_EQ(recovered->cause->context.size(), 1u);
  EXPECT_EQ(recovered->cause->context[0].key, "node.id");
  EXPECT_EQ(recovered->cause->context[0].value, "ns=2;i=5");
}

// @verifies CL-DIAG-008
// client_design.md section 8.15.2: with the SymbolicId-prefix policy on, a non-empty SymbolicId is recorded
// as the code with a "server.symbolic." prefix (flagging it server-originated, avoiding client-code
// collisions); with the policy off (default) the bare id is kept (historical behaviour), and an empty id is
// never prefixed into a bare "server.symbolic." code.
// @relation(CL-DIAG-008, scope=function)
TEST(DiagnosticToErrorDetail, PrefixSymbolicIdOptionFlagsServerOrigin)
{
  Array<String> table;
  table.payload().emplace_back("BadSensorOutOfRange");  // 0

  DiagnosticInfo info;
  info.symbolic_id() = 0;

  // Default (policy off) -> bare id.
  EXPECT_EQ(diagnostic_to_error_detail(info, table)->code, "BadSensorOutOfRange");

  // Policy on -> prefixed.
  DiagnosticDecodeOptions prefixed;
  prefixed.prefixSymbolicId = true;
  EXPECT_EQ(diagnostic_to_error_detail(info, table, prefixed)->code, "server.symbolic.BadSensorOutOfRange");

  // Empty SymbolicId is not prefixed (no bare "server.symbolic." code).
  DiagnosticInfo noId;
  EXPECT_TRUE(diagnostic_to_error_detail(noId, table, prefixed)->code.empty());
}

namespace
{
// Builds an outermost DiagnosticInfo whose inner chain is `levels` deep (each level symbolic_id=0).
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
}  // namespace

// @verifies CL-DIAG-009
// CL-DIAG-009: a chain longer than maxChainDepth is
// tail-truncated at the cap and a terminal sentinel (code "CHAIN_TRUNCATED", source
// "client.diagnostic.truncated", context omitted_depth=<N>) is inserted as a decode-bomb guard. A 50-level
// chain with cap 10 -> 10 real links + 1 sentinel = depth 11, omitted_depth 40. With the default (no cap)
// the same chain is decoded in full (falsifiability: the cap is opt-in, not always on).
// @relation(CL-DIAG-009, scope=function)
TEST(DiagnosticToErrorDetail, DepthCapTailTruncatesWithSentinel)
{
  Array<String> table;
  table.payload().emplace_back("L");  // 0
  auto chain = build_deep_chain(50);

  DiagnosticDecodeOptions capped;
  capped.maxChainDepth = 10;
  auto cappedChain = diagnostic_to_error_detail(*chain, table, capped);
  auto [depth, terminal] = walk_chain(cappedChain.get());
  EXPECT_EQ(depth, 11u);
  ASSERT_NE(terminal, nullptr);
  EXPECT_EQ(terminal->code, "CHAIN_TRUNCATED");
  EXPECT_EQ(terminal->source, "client.diagnostic.truncated");
  ASSERT_EQ(terminal->context.size(), 1u);
  EXPECT_EQ(terminal->context[0].key, "omitted_depth");
  EXPECT_EQ(terminal->context[0].value, "40");

  // Default: no cap -> full 50-level chain, no sentinel.
  auto fullChain = diagnostic_to_error_detail(*chain, table);
  auto [fullDepth, fullTerminal] = walk_chain(fullChain.get());
  EXPECT_EQ(fullDepth, 50u);
  ASSERT_NE(fullTerminal, nullptr);
  EXPECT_NE(fullTerminal->code, "CHAIN_TRUNCATED");
}

// --- format_diagnostic ---

TEST(FormatDiagnostic, MatchesToStringOfConvertedErrorDetail)
{
  Array<String> table;
  table.payload().emplace_back("CertExpired");  // 0
  table.payload().emplace_back("server.crypto");  // 1
  table.payload().emplace_back("Certificate expired");  // 2

  DiagnosticInfo info;
  info.symbolic_id() = 0;
  info.namespace_uri() = 1;
  info.localized_text() = 2;
  info.inner_status_code() = StatusCode{Status::BadCertificateTimeInvalid};
  info.additional_info() = "CN=client, expired 2026-01-01";

  auto formatted = format_diagnostic(info, table);
  auto detail = diagnostic_to_error_detail(info, table);
  auto expected = to_string(*detail);

  EXPECT_EQ(formatted, expected);
  // Verify it actually contains the key information.
  EXPECT_NE(formatted.find("CertExpired"), std::string::npos);
  EXPECT_NE(formatted.find("server.crypto"), std::string::npos);
  EXPECT_NE(formatted.find("Certificate expired"), std::string::npos);
  EXPECT_NE(formatted.find("CN=client"), std::string::npos);
}
