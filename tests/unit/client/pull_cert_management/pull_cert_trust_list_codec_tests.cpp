// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the pure PullCert TrustList codec helpers (CL-PULLCRT-005) - the LastUpdateTime
// interpretation ladder and the TrustList-body decode, extracted from PullCertificateManagerClientHost so
// their branch outcomes are unit-testable without a live GDS Connection (the section 3.1 coverage gap).

#include "ua_pull_cert_trust_list_codec.h"

#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_trust_list_data_type.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <optional>

using namespace ua;
using ua::client::detail::build_get_certificate_status_arguments;
using ua::client::detail::build_get_trust_list_arguments;
using ua::client::detail::decode_get_certificate_status_result;
using ua::client::detail::decode_get_trust_list_result;
using ua::client::detail::decode_trust_list_body;
using ua::client::detail::interpret_trust_list_last_update_time;

namespace
{

Result<CallResult> successful_call(std::vector<Variant> outputs)
{
  CallMethodResult methodResult;
  for (auto& output : outputs)
    methodResult.output_arguments().push_back(std::move(output));
  return Result<CallResult>{CallResult{std::move(methodResult)}};
}

// RATIFIED EXPECTATION CHANGE (2026-10-03, decision D5): this arm asserted a single argument, the
// certificateGroupId, which is not the Method's signature. OPC 10000-12 7.9.9: GetTrustList([in] NodeId
// applicationId, [in] NodeId certificateGroupId, [out] NodeId trustListId); a conformant GDS refuses the
// one-argument call. The arguments are now the application, then the group.
// @verifies CL-PULLCRT-005
// @relation(CL-PULLCRT-005, scope=function)
// @relation(AC-CL-PULLCRT-005-GETTRUSTLIST-NAMES-THE-APPLICATION-AND-THE-GROUP, scope=function)
TEST(PullCertTrustListCodec, GetTrustListUsesGroupAndDecodesReturnedObject)
{
  const auto arguments = build_get_trust_list_arguments(NodeId{2, 7U}, NodeId{3, 10U});
  ASSERT_EQ(arguments.size(), 2U);
  EXPECT_EQ(arguments[0].as<NodeId>(), (NodeId{2, 7U})) << "the applicationId comes first";
  EXPECT_EQ(arguments[1].as<NodeId>(), (NodeId{3, 10U})) << "then the certificateGroupId";

  const auto decoded = decode_get_trust_list_result(successful_call({Variant{NodeId{3, 20U}}}));
  ASSERT_TRUE(decoded.is_good());
  EXPECT_EQ(decoded.value(), (NodeId{3, 20U}));
}

// OPC 10000-12 7.9.10: GetCertificateStatus(applicationId, certificateGroupId, certificateTypeId) ->
// updateRequired. Both answers decode as given, so the cycle can tell a needed renewal from none.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(PullCertTrustListCodec, GetCertificateStatusSendsTheSignatureAndDecodesUpdateRequired)
{
  const auto arguments = build_get_certificate_status_arguments(NodeId{2, 7U}, NodeId{}, NodeId{0, 12557U});
  ASSERT_EQ(arguments.size(), 3U);
  EXPECT_EQ(arguments[0].as<NodeId>(), (NodeId{2, 7U}));
  EXPECT_TRUE(arguments[1].as<NodeId>().is_null()) << "a null group lets the GDS choose its default";
  EXPECT_EQ(arguments[2].as<NodeId>(), (NodeId{0, 12557U}));

  const auto required = decode_get_certificate_status_result(successful_call({Variant{true}}));
  ASSERT_TRUE(required.is_good());
  EXPECT_TRUE(required.value());
  const auto notRequired = decode_get_certificate_status_result(successful_call({Variant{false}}));
  ASSERT_TRUE(notRequired.is_good());
  EXPECT_FALSE(notRequired.value());
}

// A malformed answer is not read as "no update required": a wrong count or type is a Bad, and a Method
// failure propagates with its own status.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST(PullCertTrustListCodec, GetCertificateStatusRefusesAMalformedAnswer)
{
  EXPECT_EQ(decode_get_certificate_status_result(successful_call({})).status_code().as_status(),
    Status::BadUnexpectedError);
  EXPECT_EQ(
    decode_get_certificate_status_result(successful_call({Variant{NodeId{1, 1U}}})).status_code().as_status(),
    Status::BadTypeMismatch);
  std::shared_ptr<const ErrorDetail> detail = make_error_detail("Unknown", "unknown application", "gds");
  const auto failed = decode_get_certificate_status_result(
    Result<CallResult>{CallResult{StatusCode{Status::BadNotFound}, detail}});
  EXPECT_EQ(failed.status_code().as_status(), Status::BadNotFound);
}

TEST(PullCertTrustListCodec, GetTrustListPreservesMethodFailure)
{
  std::shared_ptr<const ErrorDetail> detail = make_error_detail("Denied", "denied", "gds.get_trust_list");
  const auto decoded = decode_get_trust_list_result(
    Result<CallResult>{CallResult{StatusCode{Status::BadUserAccessDenied}, detail}});
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadUserAccessDenied);
  EXPECT_EQ(decoded.shared_detail(), detail);
}

TEST(PullCertTrustListCodec, GetTrustListRejectsMalformedOutputs)
{
  EXPECT_EQ(
    decode_get_trust_list_result(successful_call({})).status_code().as_status(), Status::BadUnexpectedError);
  EXPECT_EQ(decode_get_trust_list_result(successful_call({Variant{42}})).status_code().as_status(),
    Status::BadTypeMismatch);
}

// Encodes a TrustListDataType to a UA-Binary body (mirrors the server's TrustList File encode).
ByteString encode_trust_list(const TrustListDataType& trustList)
{
  memory_stream_device::Dynamic device{64 * 1024, /*reserve=*/true};
  MemoryStream<memory_stream_device::Dynamic> stream{device};
  UaBinaryEncoder encoder{CodecNamespaceContext{}, stream};
  encoder.encode(EncodingLimits{}.stack_depth(), trustList);
  return device.get_data();
}

// ---- interpret_trust_list_last_update_time: the five-outcome ladder ----

// A service-level bad Result propagates verbatim (code + ErrorDetail), never a nullopt.
TEST(PullCertTrustListCodec, InterpretPropagatesServiceBad)
{
  const auto result =
    interpret_trust_list_last_update_time(Result<DataValue>{StatusCode{Status::BadUserAccessDenied}});
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadUserAccessDenied);
}

// A BAD value-quality (DataValue.status is bad, e.g. a per-node access denial) propagates - it must NOT
// degrade to nullopt (which would silently skip a needed trust-list update, CL-PULLCRT-005). This is the
// security-required branch.
TEST(PullCertTrustListCodec, InterpretPropagatesBadValueQualityNotNullopt)
{
  const auto result = interpret_trust_list_last_update_time(
    Result<DataValue>{DataValue{StatusCode{Status::BadUserAccessDenied}}});
  EXPECT_TRUE(result.is_bad()) << "a denied LastUpdateTime read must not be mistaken for 'no update'";
  EXPECT_EQ(result.status_code().as_status(), Status::BadUserAccessDenied);
}

// An empty Variant (the server published no LastUpdateTime) -> Good/nullopt (the force-download marker).
TEST(PullCertTrustListCodec, InterpretEmptyValueIsGoodNullopt)
{
  const auto result = interpret_trust_list_last_update_time(Result<DataValue>{DataValue{}});
  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().has_value()) << "an absent LastUpdateTime is nullopt (force download)";
}

// A non-empty non-DateTime value is a malformed LastUpdateTime -> the coercion error (not nullopt).
TEST(PullCertTrustListCodec, InterpretNonDateTimeValueIsCoercionError)
{
  const auto result =
    interpret_trust_list_last_update_time(Result<DataValue>{DataValue{Variant{std::int32_t{42}}}});
  EXPECT_TRUE(result.is_bad()) << "a non-DateTime LastUpdateTime is malformed, not absent";
}

// A valid DateTime value is delivered as the DateTime.
TEST(PullCertTrustListCodec, InterpretValidDateTimeIsDelivered)
{
  const DateTime when{2030, 6, 15, 12, 0, 0.0};
  const auto result = interpret_trust_list_last_update_time(Result<DataValue>{DataValue{Variant{when}}});
  ASSERT_TRUE(result.is_good());
  ASSERT_TRUE(result.value().has_value());
  EXPECT_EQ(result.value().value(), when);
}

// The trust-list update is decided only on a Good LastUpdateTime: an Uncertain value status is refused with
// Bad_InternalError (ReadAnswerUncertain) even though a DateTime is present.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertTrustListCodec, InterpretRefusesAnUncertainValueStatus)
{
  DataValue dataValue{Variant{DateTime{2030, 6, 15, 12, 0, 0.0}}};
  dataValue.status() = StatusCode{Status::UncertainLastUsableValue};
  const auto result = interpret_trust_list_last_update_time(Result<DataValue>{std::move(dataValue)});
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  EXPECT_FALSE(result.has_value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReadAnswerUncertain");
}

// An Uncertain Read answer without a value is refused the same way, and the call completes (no throw).
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertTrustListCodec, InterpretRefusesAnUncertainReadWithoutAValue)
{
  const auto result =
    interpret_trust_list_last_update_time(Result<DataValue>{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReadAnswerUncertain");
}

// GetCertificateStatus decides whether a certificate is requested, so an Uncertain Method answer is refused
// with Bad_InternalError (ServiceAnswerUncertain) rather than read as "no update required".
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertTrustListCodec, GetCertificateStatusRefusesAnUncertainAnswer)
{
  const auto result = decode_get_certificate_status_result(
    Result<CallResult>{CallResult{StatusCode{Status::UncertainLastUsableValue}}});
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  EXPECT_FALSE(result.has_value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ServiceAnswerUncertain");
}

// The TrustList Object is used only from a Good answer: an Uncertain service answer is refused with
// Bad_InternalError (ServiceAnswerUncertain); a Good subcode is Good and the Object is decoded.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertTrustListCodec, GetTrustListUsesOnlyAGoodAnswer)
{
  const auto refused =
    decode_get_trust_list_result(Result<CallResult>{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "ServiceAnswerUncertain");

  CallMethodResult methodResult;
  methodResult.output_arguments().push_back(Variant{NodeId{3, 21U}});
  const auto used = decode_get_trust_list_result(
    Result<CallResult>{CallResult{std::move(methodResult), StatusCode{Status::GoodCompletesAsynchronously}}});
  ASSERT_TRUE(used.is_good()) << used.status_code().value();
  EXPECT_EQ(used.value(), (NodeId{3, 21U}));
}

// ---- decode_trust_list_body ----

// A well-formed UA-Binary TrustListDataType body round-trips (the trusted certs survive decode).
TEST(PullCertTrustListCodec, DecodeRoundTripsAWellFormedTrustList)
{
  const ByteString firstCert{0x30, 0x82, 0x01, 0x02};  // a stand-in DER blob
  const ByteString secondCert{0xAB, 0xCD};
  TrustListDataType original;
  original.specified_lists() = 0x0F;  // all four lists specified
  original.trusted_certificates().push_back(firstCert);
  original.trusted_certificates().push_back(secondCert);

  const auto decoded = decode_trust_list_body(encode_trust_list(original));
  ASSERT_TRUE(decoded.is_good());
  EXPECT_EQ(decoded.value().specified_lists(), 0x0Fu);
  ASSERT_EQ(decoded.value().trusted_certificates().size(), 2u);
  EXPECT_EQ(decoded.value().trusted_certificates()[0], firstCert);
}

// A malformed / truncated body is a source-tagged Bad_DecodingError, never a silent empty TrustList.
TEST(PullCertTrustListCodec, DecodeMalformedBodyIsDecodingError)
{
  const auto decoded = decode_trust_list_body(ByteString{0xFF, 0xFF, 0xFF});
  EXPECT_TRUE(decoded.is_bad());
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadDecodingError);
  ASSERT_NE(decoded.shared_detail(), nullptr);
  EXPECT_EQ(decoded.shared_detail()->source, "client.tier1.pull_cert.trust_list.decode_failed");
}

// An empty body (immediate EOF) is likewise a decode failure, not an empty trust list.
TEST(PullCertTrustListCodec, DecodeEmptyBodyIsDecodingError)
{
  const auto decoded = decode_trust_list_body(ByteString{});
  EXPECT_TRUE(decoded.is_bad());
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadDecodingError);
}

// section 3.1: a BOUNDARY-ALIGNED truncation - a File truncated to just its 4-byte specifiedLists mask
// {0x0F,0x00,0x00,0x00} - leniently decodes to a Good "all-lists-specified, every-list-empty" TrustList with
// the stream position frozen exactly at body.size() (the lenient decoder never advances on an EOF-short
// read), so a plain position==size check accepts it as a silent empty trust list. The re-encode round-trip
// rejects it (a real all-empty TrustList is 20 bytes, so 4 bytes cannot be canonical). Falsifiable: a
// position-only check passes this; the round-trip fails it.
TEST(PullCertTrustListCodec, DecodeBoundaryAlignedTruncationIsDecodingError)
{
  const auto decoded = decode_trust_list_body(ByteString{0x0F, 0x00, 0x00, 0x00});
  EXPECT_TRUE(decoded.is_bad())
    << "a 4-byte TrustList File (specifiedLists mask only) is malformed, not an empty trust list";
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadDecodingError);
}

// Trailing garbage after a valid TrustList body is also rejected (the re-encode is shorter than the body).
TEST(PullCertTrustListCodec, DecodeTrailingGarbageIsDecodingError)
{
  TrustListDataType original;
  original.specified_lists() = 0x0F;  // all four (empty) lists
  ByteString body = encode_trust_list(original);
  body.push_back(std::uint8_t{0x99});  // one trailing junk byte
  const auto decoded = decode_trust_list_body(body);
  EXPECT_TRUE(decoded.is_bad()) << "trailing bytes after a valid TrustList body are malformed";
  EXPECT_EQ(decoded.status_code().as_status(), Status::BadDecodingError);
}

// section 3.1 regression: a conformant server may encode an empty array/ByteString as length 0 (legal
// UA-Binary, OPC 10000-6 section 5.1.11) rather than length -1, while the SDK encoder canonicalises empties
// to -1. The decode must ACCEPT such a body - a byte-identical round-trip would FALSE-REJECT it, silently
// dropping a legitimate trust-anchor update and breaking GDS interop (the certification target). This is a
// HAND-CRAFTED length-0 body (the SDK encoder cannot emit it): specifiedLists=all, one trusted cert, three
// length-0-empty lists. Falsifiable: a byte-identical round-trip rejects this Good body (a size round-trip
// accepts it - both empty forms are 4-byte length fields).
TEST(PullCertTrustListCodec, DecodeAcceptsLengthZeroEmptyArrays)
{
  const ByteString body{0x0F,
    0x00,
    0x00,
    0x00,  // specifiedLists = 0x0F (all four lists)
    0x01,
    0x00,
    0x00,
    0x00,  // trustedCertificates: array length 1
    0x04,
    0x00,
    0x00,
    0x00,
    0x30,
    0x82,
    0x01,
    0x02,  //   cert[0]: length 4 + DER
    0x00,
    0x00,
    0x00,
    0x00,  // trustedCrls: array length 0 (empty, NOT -1)
    0x00,
    0x00,
    0x00,
    0x00,  // issuerCertificates: length 0
    0x00,
    0x00,
    0x00,
    0x00};  // issuerCrls: length 0
  const auto decoded = decode_trust_list_body(body);
  ASSERT_TRUE(decoded.is_good())
    << "a length-0-empty TrustList from a conformant server must be accepted (GDS interop)";
  EXPECT_EQ(decoded.value().specified_lists(), 0x0Fu);
  ASSERT_EQ(decoded.value().trusted_certificates().size(), 1u);
}

}  // namespace
