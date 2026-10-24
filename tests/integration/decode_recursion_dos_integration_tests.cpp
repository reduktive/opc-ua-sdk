// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Decode-recursion DoS resistance - integration tests
///
/// A hostile peer can craft a request whose body nests structurally without bound. Here the carrier
/// is a Variant holding an Array<Variant> holding a Variant ... ~1500 levels deep. Decoding such a
/// message recurses one native frame per level; without a bound it overflows the server's stack - a
/// PRE-AUTH denial of service, because the request body is decoded before any service logic (or even
/// authorization) runs.
///
/// The StackDepth recursion-depth guard (ua_resource_budgets.h) must reject the descent cleanly during
/// decode, so the server returns a fault and keeps serving rather than crashing. The unit tests
/// UaBinaryEncodingLimitsTests.{DeeplyNestedDiagnosticInfoIsRejectedNotStackOverflow,
/// ModestlyNestedDiagnosticInfoIsAccepted} cover the decoder in isolation; this exercises the
/// END-TO-END path over a real TCP secure channel against a live server.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_read_response.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

using namespace ua;
using namespace ua::client;
using namespace ua::test_helpers;

namespace
{

/// Builds a @p depth-deep Variant: each level is an `Array<Variant>` of length 1 wrapping the level
/// below. Decoding it descends one recursion level per wrapper (decode(Variant) -> array element ->
/// decode(Variant) -> ...), which is exactly the descent the depth guard must bound.
///
/// Built iteratively here (no deep recursion in construction); only the eventual encode and the
/// object's destructor recurse, and @p depth is kept within a safe native-stack budget for the test.
Variant build_deeply_nested_variant(size_t depth)
{
  Variant current;  // innermost leaf: a Null variant
  for (size_t level = 0; level < depth; ++level)
  {
    Array<Variant> wrapper;
    wrapper.push_back(std::move(current));
    current = Variant{std::move(wrapper)};
  }
  return current;
}

/// Comfortably past StackDepth::kDefaultMaxDepth (100) so the server's depth guard fires, yet small
/// enough that building/encoding/destroying the object on the client stays well within the test's
/// native stack - including the `ulimit -s 1024` (1 MB) small-stack CI lane, which runs this test on
/// the client side too. The encoder charges no recursion-depth budget, so the client encodes and sends
/// this happily - the rejection must come from the SERVER's decode.
constexpr size_t hostileNestingDepth = 400;

}  // namespace

// A heavily-nested Write request is rejected during decode, and the server keeps serving afterwards.
TEST_F(ComplianceWithNodes, DeeplyNestedWriteRequestIsRejectedAndServerSurvives)
{
  auto hostile = build_deeply_nested_variant(hostileNestingDepth);

  auto result = mSession->attributes().try_write_sync(
    WriteRequestBuilder().write(mWritableVariableId, std::move(hostile)).build());

  // The server must reject the request rather than apply it or crash. The depth guard throws
  // BadEncodingLimitsExceeded during decode; the server turns that into a service fault keyed by the
  // request handle (decoded from the header, before the nested body), so the client sees a failed
  // Result carrying that status.
  ASSERT_FALSE(result.is_good()) << "deeply-nested request must be rejected, not accepted";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded)
    << "got status code " << result.status_code().as_uint32();

  // Server survival: a fresh channel/session can still read the node. Using a fresh channel keeps the
  // probe robust even if the hostile request tore down the original channel; the point is that the
  // server PROCESS is alive and its listener still accepts and serves connections.
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "PostAttackProbe"});
  session.activate_sync();

  auto readResp = session.attributes().read_sync(read_value(mWritableVariableId, AttributeId::Value));
  EXPECT_THAT(readResp, ServiceResultIsGood());
  ASSERT_EQ(readResp.results().size(), 1u);
  const auto& valueStatus = readResp.results()[0].status();
  EXPECT_TRUE(!valueStatus.has_value() || valueStatus->is_good())
    << "post-attack read returned a bad value status";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
