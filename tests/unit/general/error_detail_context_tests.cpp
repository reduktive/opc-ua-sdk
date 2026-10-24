// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <type_traits>

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_node_id.h"
#include "ua_server_authentication.h"
#include "ua_to_string.h"

using namespace ua;

// --- ContextKey: closed vocabulary newtype ---

// Closure is a compile-time guarantee: an off-vocabulary key cannot be
// constructed because the ContextKey constructor is private.
static_assert(!std::is_constructible_v<ContextKey, std::string_view>,
  "ContextKey must be closed: off-vocabulary keys must not compile");

TEST(ContextKey, ConstantsCarryTheirDottedKeyString)
{
  EXPECT_EQ(ContextKeys::nodeId.value(), "node.id");
  EXPECT_EQ(ContextKeys::operationIndex.value(), "operation.index");
  EXPECT_EQ(ContextKeys::sizeActual.value(), "size.actual");
  EXPECT_EQ(ContextKeys::value.value(), "value");  // the generic key does not collide with value()
}

TEST(ContextKey, EqualityComparesTheUnderlyingKey)
{
  EXPECT_EQ(ContextKeys::nodeId, ContextKeys::nodeId);
  EXPECT_NE(ContextKeys::nodeId, ContextKeys::nodeAttribute);
}

// --- ErrorDetailBuilder: facts in context, prose stays prose ---

TEST(ErrorDetailBuilder, ContextFactsLandInOrderWithVocabularyKeys)
{
  std::unique_ptr<ErrorDetail> detail =
    ErrorDetail::build("NodeIdUnknown", "node not found", "server.services.read")
      .context(ContextKeys::nodeId, "ns=2;i=4711")
      .context(ContextKeys::operationIndex, "3");

  ASSERT_TRUE(detail);
  EXPECT_EQ(detail->code, "NodeIdUnknown");
  EXPECT_EQ(detail->summary, "node not found");
  EXPECT_EQ(detail->source, "server.services.read");
  EXPECT_TRUE(detail->detail.empty());

  ASSERT_EQ(detail->context.size(), 2u);
  EXPECT_EQ(detail->context[0].key, "node.id");
  EXPECT_EQ(detail->context[0].value, "ns=2;i=4711");
  EXPECT_EQ(detail->context[1].key, "operation.index");
  EXPECT_EQ(detail->context[1].value, "3");
}

TEST(ErrorDetailBuilder, CauseFromStatusCodeLiftsInnerStatusAndChainLosslessly)
{
  StatusCode inner{
    Status::BadNodeIdUnknown, make_error_detail("InnerCode", "inner summary", "server.namespace.read")};

  std::unique_ptr<ErrorDetail> detail =
    ErrorDetail::build("ReadFailed", "read failed", "client.tier1.connection.read")
      .context(ContextKeys::sessionId, "ns=1;i=99")
      .cause(inner);

  ASSERT_TRUE(detail);
  EXPECT_EQ(detail->innerStatus, inner.value());
  ASSERT_TRUE(detail->cause);
  EXPECT_EQ(detail->cause->code, "InnerCode");
  ASSERT_EQ(detail->context.size(), 1u);
  EXPECT_EQ(detail->context[0].key, "session.id");
}

TEST(ErrorDetailBuilder, DropsInWhereMakeErrorDetailIsConsumed)
{
  // The builder must substitute for make_error_detail() (which returns
  // unique_ptr<ErrorDetail>) at the consumption sites the sweep will rewrite:
  // StatusCode{Status, ...} and Result<T>{StatusCode}.
  StatusCode sc{Status::BadInternalError,
    ErrorDetail::build("WriteFailed", "write rejected", "server.services.write")
      .context(ContextKeys::nodeId, "ns=2;i=5")};
  ASSERT_TRUE(sc.shared_detail());
  ASSERT_EQ(sc.shared_detail()->context.size(), 1u);
  EXPECT_EQ(sc.shared_detail()->context[0].key, "node.id");

  VoidResult r{StatusCode{Status::BadNodeIdUnknown,
    ErrorDetail::build("NodeIdUnknown", "node not found", "server.services.read")
      .context(ContextKeys::nodeId, "ns=2;i=5")}};
  EXPECT_TRUE(r.is_bad());
  ASSERT_TRUE(r.status_code().shared_detail());
  EXPECT_EQ(r.status_code().shared_detail()->context.size(), 1u);
}

TEST(ErrorDetailBuilder, ConvertsToSharedDetailWithoutDoneTerminal)
{
  // The shared_ptr<const ErrorDetail> conversion lets the builder drop into braced-init
  // sinks (StatusCode/Result) with a single user conversion -- no  needed.
  StatusCode sc{Status::BadNodeIdUnknown,
    ErrorDetail::build("NodeIdUnknown", "node not found", "server.read")
      .context(ContextKeys::nodeId, "ns=2;i=5")};
  ASSERT_TRUE(sc.shared_detail());
  ASSERT_EQ(sc.shared_detail()->context.size(), 1u);
  EXPECT_EQ(sc.shared_detail()->context[0].value, "ns=2;i=5");

  VoidResult r{StatusCode{
    Status::BadInternalError, ErrorDetail::build("Boom", "boom", "src").context(ContextKeys::index, "3")}};
  ASSERT_TRUE(r.status_code().shared_detail());
}

TEST(ErrorDetailBuilder, UaExceptionCarriesBuilderDetailWithoutDoneTerminal)
{
  try
  {
    throw UaException{Status::BadResourceUnavailable,
      ErrorDetail::build("WriteFailed", "write rejected", "server.write")
        .context(ContextKeys::nodeId, "ns=2;i=7")};
  }
  catch (const UaException& e)
  {
    ASSERT_NE(e.detail(), nullptr);
    EXPECT_EQ(e.detail()->code, "WriteFailed");
    ASSERT_EQ(e.detail()->context.size(), 1u);
    EXPECT_EQ(e.detail()->context[0].key, "node.id");
  }
}

TEST(ErrorDetailBuilder, TypedContextValuesRenderCanonically)
{
  // Pass a NodeId / integers directly; the builder renders them via the canonical
  // error_detail_render (NodeId -> ua::to_string, integer -> std::to_string).
  std::unique_ptr<ErrorDetail> d =
    ErrorDetail::build("TooManyNodes", "request exceeds limit", "server.browse")
      .context(ContextKeys::nodeId, NodeId{2, 4711u})
      .context(ContextKeys::sizeActual, 5000)
      .context(ContextKeys::sizeMax, static_cast<size_t>(1000));
  ASSERT_EQ(d->context.size(), 3u);
  EXPECT_EQ(d->context[0].key, "node.id");
  EXPECT_EQ(d->context[0].value, "ns=2;i=4711");
  EXPECT_EQ(d->context[1].value, "5000");
  EXPECT_EQ(d->context[2].value, "1000");
}

TEST(ErrorDetailBuilder, DetailSetsExtendedProse)
{
  std::unique_ptr<ErrorDetail> detail =
    ErrorDetail::build("Code", "summary", "source").detail("extended prose");

  ASSERT_TRUE(detail);
  EXPECT_EQ(detail->detail, "extended prose");
}

// --- to_string(ErrorDetail) renders the structured context ---

TEST(ErrorDetailToString, RendersEachContextFactOnItsOwnLine)
{
  std::unique_ptr<ErrorDetail> detail =
    ErrorDetail::build("TooManyNodes", "request exceeds limit", "server.services.browse")
      .context(ContextKeys::sizeActual, "5000")
      .context(ContextKeys::sizeMax, "1000");

  const std::string rendered = to_string(*detail);

  EXPECT_NE(rendered.find("TooManyNodes: request exceeds limit"), std::string::npos);
  EXPECT_NE(rendered.find("size.actual = 5000"), std::string::npos);
  EXPECT_NE(rendered.find("size.max = 1000"), std::string::npos);
}

// --- to_string(UserTokenKind): symbolic, capitalised (the token.kind renderer) ---

TEST(UserTokenKindToString, RendersSymbolicCapitalisedNames)
{
  using ua::server::UserTokenKind;
  EXPECT_EQ(to_string(UserTokenKind::Anonymous), "Anonymous");
  EXPECT_EQ(to_string(UserTokenKind::UserName), "UserName");
  EXPECT_EQ(to_string(UserTokenKind::X509), "X509");
  EXPECT_EQ(to_string(UserTokenKind::IssuedToken), "IssuedToken");
  EXPECT_EQ(to_string(UserTokenKind::Unsupported), "Unsupported");
}

// --- DiagnosticInfo.AdditionalInfo JSON bridge (encode/decode round-trip) ---

TEST(AdditionalInfoBridge, RoundTripsContextAndDetailThroughJson)
{
  std::unique_ptr<ErrorDetail> src =
    ErrorDetail::build("WriteFailed", "write rejected", "server.services.write")
      .detail("storage backend unavailable")
      .context(ContextKeys::nodeId, "ns=2;i=4711")
      .context(ContextKeys::operationIndex, "0");

  const std::string wire = detail::make_additional_info(*src);
  EXPECT_NE(wire.find("$uactx"), std::string::npos);  // marker present

  ErrorDetail out;
  detail::parse_additional_info(wire, out);

  EXPECT_EQ(out.detail, "storage backend unavailable");
  ASSERT_EQ(out.context.size(), 2u);
  EXPECT_EQ(out.context[0].key, "node.id");
  EXPECT_EQ(out.context[0].value, "ns=2;i=4711");
  EXPECT_EQ(out.context[1].key, "operation.index");
  EXPECT_EQ(out.context[1].value, "0");
}

TEST(AdditionalInfoBridge, PreservesValuesWithDelimitersQuotesAndNewlines)
{
  // The values that would break a hand-rolled "k=v; k=v" scheme.
  ErrorDetail src;
  src.context.push_back(NamedValue{"node.id", "ns=2;s=Production/MachineA;Speed"});
  src.context.push_back(NamedValue{"value", "he said \"hi\"\nline2\tunicode-\xC3\xA9"});

  const std::string wire = detail::make_additional_info(src);
  ErrorDetail out;
  detail::parse_additional_info(wire, out);

  ASSERT_EQ(out.context.size(), 2u);
  EXPECT_EQ(out.context[0].value, "ns=2;s=Production/MachineA;Speed");
  EXPECT_EQ(out.context[1].value, "he said \"hi\"\nline2\tunicode-\xC3\xA9");
}

TEST(AdditionalInfoBridge, ContextlessLayerEmitsPlainProseNotJson)
{
  ErrorDetail src;
  src.detail = "just human prose";
  const std::string wire = detail::make_additional_info(src);
  EXPECT_EQ(wire, "just human prose");  // no JSON, no marker
  EXPECT_EQ(wire.find("$uactx"), std::string::npos);
}

TEST(AdditionalInfoBridge, NonSdkVendorTextFallsBackToOpaqueDetail)
{
  ErrorDetail out;
  detail::parse_additional_info("stack trace: frobnicate() at foo.cpp:42", out);
  EXPECT_EQ(out.detail, "stack trace: frobnicate() at foo.cpp:42");
  EXPECT_TRUE(out.context.empty());
}

TEST(AdditionalInfoBridge, ForeignJsonWithoutMarkerIsTreatedAsOpaque)
{
  // Valid JSON object but not ours (no $uactx) -> opaque, not mis-parsed.
  const std::string foreign = R"({"some":"other","payload":1})";
  ErrorDetail out;
  detail::parse_additional_info(foreign, out);
  EXPECT_EQ(out.detail, foreign);
  EXPECT_TRUE(out.context.empty());
}

TEST(AdditionalInfoBridge, BoundsEntryCountAgainstHostileInput)
{
  ErrorDetail src;
  for (int i = 0; i < 500; ++i)
  {
    src.context.push_back(NamedValue{"k" + std::to_string(i), "v"});
  }
  const std::string wire = detail::make_additional_info(src);
  ErrorDetail out;
  detail::parse_additional_info(wire, out);
  EXPECT_LE(out.context.size(), 128u);  // capped, does not blow up
}

TEST(AdditionalInfoBridge, DuplicateKeysArePreservedInOrder)
{
  // The vector data model permits duplicate keys; the array wire format must not
  // collapse them (a JSON object would, last-wins).
  ErrorDetail src;
  src.context.push_back(NamedValue{"value", "first"});
  src.context.push_back(NamedValue{"value", "second"});

  ErrorDetail out;
  detail::parse_additional_info(detail::make_additional_info(src), out);
  ASSERT_EQ(out.context.size(), 2u);
  EXPECT_EQ(out.context[0].value, "first");
  EXPECT_EQ(out.context[1].value, "second");
}

TEST(AdditionalInfoBridge, BestEffortParsesFutureVersion)
{
  // Additive format: an unknown version still parses known fields.
  ErrorDetail out;
  detail::parse_additional_info(R"({"$uactx":2,"ctx":[["node.id","ns=2;i=5"]]})", out);
  ASSERT_EQ(out.context.size(), 1u);
  EXPECT_EQ(out.context[0].key, "node.id");
}

TEST(AdditionalInfoBridge, NonIntegerMarkerIsTreatedAsOpaque)
{
  const std::string blob = R"({"$uactx":"nope","ctx":[["k","v"]]})";
  ErrorDetail out;
  detail::parse_additional_info(blob, out);
  EXPECT_EQ(out.detail, blob);
  EXPECT_TRUE(out.context.empty());
}

TEST(AdditionalInfoBridge, TruncatesOverlongValueToCap)
{
  ErrorDetail src;
  src.context.push_back(NamedValue{"value", std::string(9000, 'a')});
  ErrorDetail out;
  detail::parse_additional_info(detail::make_additional_info(src), out);
  ASSERT_EQ(out.context.size(), 1u);
  EXPECT_EQ(out.context[0].value.size(), 8u * 1024u);  // kMaxValueLength
}

TEST(AdditionalInfoBridge, EmptyValueRoundTrips)
{
  ErrorDetail src;
  src.context.push_back(NamedValue{"value", ""});
  ErrorDetail out;
  detail::parse_additional_info(detail::make_additional_info(src), out);
  ASSERT_EQ(out.context.size(), 1u);
  EXPECT_EQ(out.context[0].value, "");
}

TEST(AdditionalInfoBridge, NonPairCtxElementsAreSkipped)
{
  ErrorDetail out;
  detail::parse_additional_info(R"({"$uactx":1,"ctx":[["ok","v"],"notapair",["k2","v2"],["onlyone"]]})", out);
  ASSERT_EQ(out.context.size(), 2u);
  EXPECT_EQ(out.context[0].key, "ok");
  EXPECT_EQ(out.context[1].key, "k2");
}

TEST(AdditionalInfoBridge, MalformedJsonStartingWithBraceFallsBackToOpaque)
{
  const std::string truncated = R"({"$uactx":1,"ctx":[["node.id","ns=2)";
  ErrorDetail out;
  detail::parse_additional_info(truncated, out);
  EXPECT_EQ(out.detail, truncated);
  EXPECT_TRUE(out.context.empty());
}

// -- A builder chain can be returned from a helper ---------------------------------------
//
// The builder holds its detail in a unique_ptr, so the copy constructor is implicitly deleted.
// The chaining methods used to return ErrorDetailBuilder& - an LVALUE - so returning a chain by
// value copy-initialised from an lvalue, picked the deleted copy constructor, and failed to
// compile. Not a lifetime problem: the temporary is still alive at the return. The rvalue-
// qualified twins make a chain on a temporary an xvalue, so the return moves instead.
//
// These tests are the compile-time arm as much as the run-time one: without the twins, the
// helper below does not build.

namespace
{
/// Builds a detail and hands it back - the shape that could not be written before.
ErrorDetailBuilder describe_unknown_node(const NodeId& node)
{
  return ErrorDetail::build("NodeIdUnknown", "node not found", "server.services.read")
    .context(ContextKeys::nodeId, node);
}

/// Chained across several calls, and with a cause, still returnable.
ErrorDetailBuilder describe_wrapped_failure(const NodeId& node, StatusCode inner)
{
  return ErrorDetail::build("ReadFailed", "read failed", "server.services.read")
    .context(ContextKeys::nodeId, node)
    .cause(inner);
}
}  // namespace

// @relation(AC-COMP-SDK-POST-ERROR-CHAIN, scope=function)
TEST(ErrorDetailBuilderChaining, AChainOnATemporaryCanBeReturnedFromAHelper)
{
  const NodeId node{2, uint32_t{4711}};
  const std::shared_ptr<const ErrorDetail> detail = describe_unknown_node(node);

  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "NodeIdUnknown");
  EXPECT_EQ(detail->summary, "node not found");
  ASSERT_EQ(detail->context.size(), 1u);
  EXPECT_EQ(detail->context[0].key, ContextKeys::nodeId.value());
  EXPECT_EQ(detail->context[0].value, ua::to_string(node));
}

// @relation(AC-COMP-SDK-POST-ERROR-CHAIN, scope=function)
TEST(ErrorDetailBuilderChaining, AReturnedChainKeepsItsCause)
{
  const NodeId node{2, uint32_t{4711}};
  const std::shared_ptr<const ErrorDetail> detail =
    describe_wrapped_failure(node, StatusCode{Status::BadNodeIdUnknown});

  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "ReadFailed");
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadNodeIdUnknown}.value())
    << "the cause must survive being returned out of the helper";
}

// @relation(AC-COMP-SDK-POST-ERROR-CHAIN, scope=function)
TEST(ErrorDetailBuilderChaining, ChainingOnAnLvalueStillWorksInPlace)
{
  // The lvalue-qualified overloads keep the in-place style working unchanged: this is what
  // nearly every call site in the SDK does, and none of them had to move.
  auto builder = ErrorDetail::build("InPlace", "built in place", "test");
  builder.context(ContextKeys::nodeId, NodeId{1, uint32_t{7}});
  builder.detail("extended prose");

  const std::shared_ptr<const ErrorDetail> detail = builder;
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "InPlace");
  EXPECT_EQ(detail->detail, "extended prose");
  ASSERT_EQ(detail->context.size(), 1u);
}

// --- describe(): the detail when there is one, the plain code when there is not ---
//
// to_string(const StatusCode&) renders only the numeric status and drops any attached
// detail. describe() is the accessor that does not, so these tests pin BOTH halves of
// its contract: what it adds over to_string, and that it never loses the caller's code.

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, WithoutADetailRendersThePlainCode)
{
  const StatusCode bare{Status::BadTypeMismatch};

  ASSERT_EQ(bare.detail(), nullptr);
  EXPECT_EQ(describe(bare), to_string(bare));
  EXPECT_NE(describe(bare).find("BadTypeMismatch"), std::string::npos);
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, AGoodStatusRendersThePlainCode)
{
  const StatusCode good{};

  EXPECT_EQ(describe(good), to_string(good));
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, WithADetailRendersTheStructuredContextToStringDrops)
{
  const StatusCode failure{Status::BadTypeMismatch,
    ErrorDetail::build("TypeMismatch", "variant held the wrong type", "core_vocabulary")
      .context(ContextKeys::typeExpected, "Double")
      .context(ContextKeys::typeActual, "Int32")
      .cause(StatusCode{Status::BadTypeMismatch})};

  const std::string described = describe(failure);

  // The facts to_string(StatusCode) discards.
  EXPECT_NE(described.find("type.expected = Double"), std::string::npos);
  EXPECT_NE(described.find("type.actual = Int32"), std::string::npos);
  EXPECT_NE(described.find("variant held the wrong type"), std::string::npos);
  // And the code itself is still there.
  EXPECT_NE(described.find("BadTypeMismatch"), std::string::npos);
  // Which to_string alone would not have given us.
  EXPECT_EQ(to_string(failure).find("type.expected"), std::string::npos);
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, DoesNotPrintTheCodeTwiceWhenTheDetailAlreadyCarriesIt)
{
  const StatusCode failure{Status::BadNodeIdUnknown,
    ErrorDetail::build("NodeIdUnknown", "node not found", "server.read")
      .cause(StatusCode{Status::BadNodeIdUnknown})};

  const std::string described = describe(failure);

  size_t occurrences = 0;
  for (size_t at = described.find("BadNodeIdUnknown"); at != std::string::npos;
       at = described.find("BadNodeIdUnknown", at + 1))
  {
    ++occurrences;
  }
  EXPECT_EQ(occurrences, 1U) << described;
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, NamesTheCarryingCodeWhenTheDetailHasNoInnerStatus)
{
  // A detail built without .cause() carries no inner status, so to_string(ErrorDetail)
  // prints no code at all. describe() must not lose the code the caller is holding.
  const StatusCode failure{
    Status::BadNodeIdUnknown, ErrorDetail::build("NodeIdUnknown", "node not found", "server.read")};

  ASSERT_TRUE(failure.detail());
  ASSERT_EQ(to_string(*failure.detail()).find("BadNodeIdUnknown"), std::string::npos);

  const std::string described = describe(failure);
  EXPECT_NE(described.find("BadNodeIdUnknown"), std::string::npos) << described;
  EXPECT_NE(described.find("node not found"), std::string::npos) << described;
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, NamesTheCarryingCodeWhenItDiffersFromTheDetailsInnerStatus)
{
  // A layer that reports one code while its detail records the cause's: the reader must
  // see the code the caller actually received, not only the one further down the chain.
  const StatusCode failure{Status::BadInternalError,
    ErrorDetail::build("ReadFailed", "read failed", "client.read")
      .cause(StatusCode{Status::BadNodeIdUnknown})};

  const std::string described = describe(failure);

  EXPECT_NE(described.find("BadInternalError"), std::string::npos) << described;
  EXPECT_NE(described.find("BadNodeIdUnknown"), std::string::npos) << described;
  EXPECT_LT(described.find("BadInternalError"), described.find("BadNodeIdUnknown")) << described;
}

// @relation(AC-COMP-SDK-POST-STATUS-DESCRIBE, scope=function)
TEST(DescribeStatusCode, KeepsTheWholeCauseChain)
{
  const StatusCode inner{
    Status::BadCertificateUntrusted, make_error_detail("ChainValidationFailed", "chain rejected", "pki")};
  const StatusCode outer{Status::BadSecurityChecksFailed,
    ErrorDetail::build("HandshakeFailed", "handshake rejected", "channel").cause(inner)};

  const std::string described = describe(outer);

  EXPECT_NE(described.find("caused by:"), std::string::npos) << described;
  EXPECT_NE(described.find("chain rejected"), std::string::npos) << described;
  EXPECT_NE(described.find("handshake rejected"), std::string::npos) << described;
}
