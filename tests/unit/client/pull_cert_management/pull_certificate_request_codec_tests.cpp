// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit controls for the Part 12 CertificateDirectory Start/FinishRequest wire codec (CL-PULLCRT-003).

#include "ua_pull_certificate_request_codec.h"

#include "ua_call_method_result.h"
#include "ua_error_detail.h"
#include "ua_status.h"

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::client::detail;

namespace
{

Result<CallResult> successful_call(std::vector<Variant> outputs)
{
  CallMethodResult methodResult;
  for (auto& output : outputs)
  {
    methodResult.output_arguments().push_back(std::move(output));
  }
  return Result<CallResult>{CallResult{std::move(methodResult)}};
}

TEST(PullCertificateRequestCodec, SigningArgumentsHaveNormativeOrder)
{
  StartCertificateRequestWireParams params;
  params.applicationId = NodeId{2, 1U};
  params.certificateGroupId = NodeId{2, 2U};
  params.certificateTypeId = NodeId{2, 3U};
  params.certificateRequest = ByteString{0x30, 0x01};

  const auto result = build_start_certificate_request_arguments(std::move(params));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 4U);
  EXPECT_EQ(result.value()[0].as<NodeId>(), (NodeId{2, 1U}));
  EXPECT_EQ(result.value()[1].as<NodeId>(), (NodeId{2, 2U}));
  EXPECT_EQ(result.value()[2].as<NodeId>(), (NodeId{2, 3U}));
  EXPECT_EQ(result.value()[3].as<ByteString>(), (ByteString{0x30, 0x01}));
}

TEST(PullCertificateRequestCodec, SigningRequestRejectsEmptyCsrWithDetail)
{
  const auto result = build_start_certificate_request_arguments(StartCertificateRequestWireParams{});
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.pull_cert.certificate_request.codec");
}

// @relation(AC-CL-PULLCRT-005-A-GDS-GENERATED-KEY-IS-REQUESTED-UNPROTECTED-AND-HELD-UNDER-THE-APPLICATION-CREDENTIAL, scope=function)
TEST(PullCertificateRequestCodec, NewKeyPairArgumentsHaveNormativeOrderAndTypes)
{
  StartCertificateRequestWireParams params;
  params.applicationId = NodeId{2, 1U};
  params.certificateGroupId = NodeId{2, 2U};
  params.certificateTypeId = NodeId{2, 3U};
  params.newKeyPair = true;
  params.subjectName = "CN=Client";
  params.domainNames = {"client.example", "client.local"};
  params.privateKeyFormat = "PEM";

  const auto result = build_start_certificate_request_arguments(std::move(params));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 7U);
  EXPECT_EQ(result.value()[0].as<NodeId>(), (NodeId{2, 1U}));
  EXPECT_EQ(result.value()[1].as<NodeId>(), (NodeId{2, 2U}));
  EXPECT_EQ(result.value()[2].as<NodeId>(), (NodeId{2, 3U}));
  EXPECT_EQ(result.value()[3].as<String>(), String{"CN=Client"});
  const auto& domains = result.value()[4].as<Array<String>>();
  ASSERT_EQ(domains.size(), 2U);
  EXPECT_EQ(domains[0], String{"client.example"});
  EXPECT_EQ(result.value()[5].as<String>(), String{"PEM"});
  // RATIFIED (owner decision 2026-10-03): the key is always requested without a password, so it is returned
  // unprotected (OPC 10000-12 7.9.4/7.9.5) and read with the application's own Crypto credential.
  EXPECT_EQ(result.value()[6].as<String>(), String{}) << "privateKeyPassword is empty";
}

TEST(PullCertificateRequestCodec, StartDecodesNodeId)
{
  const auto result = decode_start_certificate_request_result(successful_call({Variant{NodeId{3, 900U}}}));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), (NodeId{3, 900U}));
}

TEST(PullCertificateRequestCodec, StartPreservesOuterAndMethodErrorDetails)
{
  std::shared_ptr<const ErrorDetail> outerDetail = make_error_detail("Outer", "outer", "outer.source");
  const auto outer =
    decode_start_certificate_request_result(Result<CallResult>{StatusCode{Status::BadTimeout}, outerDetail});
  EXPECT_EQ(outer.status_code().as_status(), Status::BadTimeout);
  EXPECT_EQ(outer.shared_detail(), outerDetail);

  std::shared_ptr<const ErrorDetail> methodDetail = make_error_detail("Method", "pending", "method.source");
  const auto method = decode_start_certificate_request_result(
    Result<CallResult>{CallResult{StatusCode{Status::BadNothingToDo}, methodDetail}});
  EXPECT_EQ(method.status_code().as_status(), Status::BadNothingToDo);
  EXPECT_EQ(method.shared_detail(), methodDetail);
}

TEST(PullCertificateRequestCodec, StartRejectsWrongOutputCountAndType)
{
  const auto count = decode_start_certificate_request_result(successful_call({}));
  EXPECT_EQ(count.status_code().as_status(), Status::BadUnexpectedError);
  ASSERT_NE(count.shared_detail(), nullptr);

  const auto type = decode_start_certificate_request_result(successful_call({Variant{42}}));
  EXPECT_EQ(type.status_code().as_status(), Status::BadTypeMismatch);
  ASSERT_NE(type.shared_detail(), nullptr);
}

TEST(PullCertificateRequestCodec, FinishArgumentsAreApplicationThenRequest)
{
  const auto arguments = build_finish_certificate_request_arguments(NodeId{4, 10U}, NodeId{4, 11U});
  ASSERT_EQ(arguments.size(), 2U);
  EXPECT_EQ(arguments[0].as<NodeId>(), (NodeId{4, 10U}));
  EXPECT_EQ(arguments[1].as<NodeId>(), (NodeId{4, 11U}));
}

TEST(PullCertificateRequestCodec, FinishDecodesAllOutputs)
{
  Array<ByteString> issuers{ByteString{0x03}, ByteString{0x04}};
  const auto result = decode_finish_certificate_request_result(
    successful_call({Variant{ByteString{0x01}}, Variant{ByteString{0x02}}, Variant{issuers}}));

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().certificate, (ByteString{0x01}));
  EXPECT_EQ(result.value().privateKey, (ByteString{0x02}));
  EXPECT_EQ(result.value().issuerCertificates, issuers.payload());
}

// @verifies CL-PULLCRT-003
// @relation(CL-PULLCRT-003, scope=function)
TEST(PullCertificateRequestCodec, FinishPreservesPendingStatusAndDetail)
{
  std::shared_ptr<const ErrorDetail> detail = make_error_detail("Pending", "approval pending", "gds.finish");
  const auto result = decode_finish_certificate_request_result(
    Result<CallResult>{CallResult{StatusCode{Status::BadNothingToDo}, detail}});
  EXPECT_EQ(result.status_code().as_status(), Status::BadNothingToDo);
  EXPECT_EQ(result.shared_detail(), detail);
}

TEST(PullCertificateRequestCodec, FinishRejectsEveryMalformedOutputShape)
{
  EXPECT_EQ(decode_finish_certificate_request_result(successful_call({})).status_code().as_status(),
    Status::BadUnexpectedError);

  Array<ByteString> issuers;
  EXPECT_EQ(decode_finish_certificate_request_result(
              successful_call({Variant{42}, Variant{ByteString{}}, Variant{issuers}}))
              .status_code()
              .as_status(),
    Status::BadTypeMismatch);
  EXPECT_EQ(decode_finish_certificate_request_result(
              successful_call({Variant{ByteString{}}, Variant{42}, Variant{issuers}}))
              .status_code()
              .as_status(),
    Status::BadTypeMismatch);
  EXPECT_EQ(decode_finish_certificate_request_result(
              successful_call({Variant{ByteString{}}, Variant{ByteString{}}, Variant{42}}))
              .status_code()
              .as_status(),
    Status::BadTypeMismatch);
}

// The pull cycle acts on a Start answer only when Good: an Uncertain answer, from the service or from the
// Method, is refused with Bad_InternalError (ServiceAnswerUncertain) and no requestId is decoded.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertificateRequestCodec, StartRefusesAnUncertainAnswerAtEitherLayer)
{
  const auto outer =
    decode_start_certificate_request_result(Result<CallResult>{StatusCode{Status::UncertainLastUsableValue}});
  EXPECT_EQ(outer.status_code().as_status(), Status::BadInternalError);
  EXPECT_FALSE(outer.has_value());
  ASSERT_NE(outer.shared_detail(), nullptr);
  EXPECT_EQ(outer.shared_detail()->code, "ServiceAnswerUncertain");

  const auto method = decode_start_certificate_request_result(
    Result<CallResult>{CallResult{StatusCode{Status::UncertainLastUsableValue}}});
  EXPECT_EQ(method.status_code().as_status(), Status::BadInternalError);
  EXPECT_FALSE(method.has_value());
  ASSERT_NE(method.shared_detail(), nullptr);
  EXPECT_EQ(method.shared_detail()->code, "ServiceAnswerUncertain");
}

// An Uncertain FinishRequest answer is refused with Bad_InternalError (ServiceAnswerUncertain): it is neither
// a delivered certificate nor the Bad_NothingToDo that keeps the request pending.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertificateRequestCodec, FinishRefusesAnUncertainAnswer)
{
  const auto result = decode_finish_certificate_request_result(
    Result<CallResult>{CallResult{StatusCode{Status::UncertainLastUsableValue}}});
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  EXPECT_FALSE(result.has_value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ServiceAnswerUncertain");
}

// A Good subcode on the Method's answer is Good: the requestId is decoded and used.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(PullCertificateRequestCodec, StartUsesAGoodSubcodeAnswer)
{
  CallMethodResult methodResult;
  methodResult.output_arguments().push_back(Variant{NodeId{3, 901U}});
  const auto result = decode_start_certificate_request_result(
    Result<CallResult>{CallResult{std::move(methodResult), StatusCode{Status::GoodCompletesAsynchronously}}});
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(result.value(), (NodeId{3, 901U}));
}

}  // namespace
