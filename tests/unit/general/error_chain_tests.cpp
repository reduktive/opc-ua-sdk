// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include <memory>
#include <string>
#include <vector>

using namespace ua;

namespace
{
// Builds a bad Result<int> carrying a 2-link ErrorDetail chain (outer -> inner).
Result<int> make_two_link_bad_result()
{
  auto inner = std::make_shared<ErrorDetail>();
  inner->code = "InnerCode";
  inner->source = "server.write";
  inner->summary = "inner summary";

  auto outer = std::make_shared<ErrorDetail>();
  outer->code = "OuterCode";
  outer->source = "client.tier1.connection.write";
  outer->summary = "outer summary";
  outer->innerStatus = StatusCode{Status::BadTimeout}.value();
  outer->cause = inner;

  return Result<int>{StatusCode{Status::BadTimeout, outer}};
}
}  // namespace

// --- ErrorChainView ---

// @verifies CL-DIAG-013
// client_design.md section 7.10.1: ErrorChainView iterates a chain outermost-first and reports its depth; a
// status with no detail is an empty view (depth 0).
// @relation(CL-DIAG-013, scope=function)
TEST(ErrorChainView, IteratesOutermostFirstAndReportsDepth)
{
  auto bad = make_two_link_bad_result();

  ErrorChainView view{bad.status_code()};
  EXPECT_EQ(view.depth(), 2u);

  std::vector<std::string> codes;
  for (const auto& link : view)
  {
    codes.push_back(link.code);
  }
  ASSERT_EQ(codes.size(), 2u);
  EXPECT_EQ(codes[0], "OuterCode");  // outermost first
  EXPECT_EQ(codes[1], "InnerCode");

  EXPECT_EQ(ErrorChainView{StatusCode{Status::Good}}.depth(), 0u);
}

// @verifies CL-DIAG-013
// The StatusCode overload keeps the chain alive, so a view over a temporary status_code() (returned by
// value) does not dangle. (A raw-pointer view would read freed memory here.)
// @relation(CL-DIAG-013, scope=function)
TEST(ErrorChainView, SafeOverTemporaryStatusCode)
{
  auto bad = make_two_link_bad_result();

  EXPECT_EQ(ErrorChainView{bad.status_code()}.depth(), 2u);

  std::vector<std::string> codes;
  for (const auto& link : ErrorChainView{bad.status_code()})
  {
    codes.push_back(link.code);
  }
  ASSERT_EQ(codes.size(), 2u);
  EXPECT_EQ(codes[0], "OuterCode");
}

// --- ua::format ---

// @verifies CL-DIAG-013
// client_design.md section 7.10.1: ua::format renders the chain outermost-first with stable, deterministic
// output including context; a status with no detail renders as the bare status string.
// @relation(CL-DIAG-013, scope=function)
TEST(ErrorFormat, RendersChainOutermostFirstDeterministically)
{
  auto bad = make_two_link_bad_result();
  const auto text = format(bad.status_code());

  const auto posOuter = text.find("OuterCode");
  const auto posInner = text.find("InnerCode");
  ASSERT_NE(posOuter, std::string::npos);
  ASSERT_NE(posInner, std::string::npos);
  EXPECT_LT(posOuter, posInner) << "outermost link must render before its inner cause";

  // Deterministic: same input -> byte-identical output.
  EXPECT_EQ(text, format(bad.status_code()));

  // No detail -> bare status text (distinct from the chain rendering: falsifiable).
  EXPECT_EQ(format(StatusCode{Status::BadTimeout}), to_string(StatusCode{Status::BadTimeout}));
}

// @verifies CL-DIAG-013
// format must include the TOP-LEVEL StatusCode value, not just the outermost link's inner-cause status.
// The canonical failure shape is `StatusCode{X, detail}` where the detail's innerStatus is Good (or a
// different code) - to_string(ErrorDetail) alone renders only innerStatus, so a naive delegation drops X.
// @relation(CL-DIAG-013, scope=function)
TEST(ErrorFormat, IncludesTopLevelStatusDistinctFromInnerCauseStatus)
{
  auto detail = std::make_shared<ErrorDetail>();
  detail->code = "Wrapper";
  detail->source = "comp";
  detail->summary = "wrapped";
  detail->innerStatus = StatusCode{Status::Good}.value();  // no inner-cause status to render

  const StatusCode status{Status::BadInternalError, detail};
  const auto text = format(status);

  EXPECT_NE(text.find("BadInternalError"), std::string::npos)
    << "format dropped the top-level status (0x80020000); got:\n"
    << text;
  EXPECT_NE(text.find("Wrapper"), std::string::npos) << "format lost the chain; got:\n" << text;
}

// --- ua::annotate ---

// @verifies CL-DIAG-014
// client_design.md section 8.15.5: annotate on a BAD result adds a new outermost link and preserves the
// existing chain beneath (2-link chain -> 3 links; the original two unchanged; numeric status preserved).
// @relation(CL-DIAG-014, scope=function)
TEST(ErrorAnnotate, BadResultGainsOutermostLinkPreservingChain)
{
  auto bad = make_two_link_bad_result();

  auto annotated =
    annotate(std::move(bad), "USER_WRITE_FAILED", "batch write failed", "myapp.batch", {{"batch_id", "7"}});

  ASSERT_TRUE(annotated.is_bad());
  EXPECT_EQ(annotated.status_code().value(), StatusCode{Status::BadTimeout}.value());

  ErrorChainView view{annotated.status_code()};
  EXPECT_EQ(view.depth(), 3u);

  auto it = view.begin();
  EXPECT_EQ(it->code, "USER_WRITE_FAILED");  // new outermost
  EXPECT_EQ(it->source, "myapp.batch");
  ASSERT_EQ(it->context.size(), 1u);
  EXPECT_EQ(it->context[0].key, "batch_id");
  EXPECT_EQ(it->context[0].value, "7");
  ++it;
  EXPECT_EQ(it->code, "OuterCode");  // original chain unchanged beneath
  ++it;
  EXPECT_EQ(it->code, "InnerCode");
}

// @verifies CL-DIAG-014
// annotate on a GOOD result is a no-op: it stays good, keeps its value, and has an empty (depth-0) chain.
// @relation(CL-DIAG-014, scope=function)
TEST(ErrorAnnotate, GoodResultIsPassthrough)
{
  Result<int> good{42};

  auto annotated = annotate(std::move(good), "IGNORED", "should not appear", "myapp.batch");

  ASSERT_TRUE(annotated.is_good());
  EXPECT_EQ(annotated.value(), 42);
  EXPECT_EQ(ErrorChainView{annotated.status_code()}.depth(), 0u);
}

// annotate on an UNCERTAIN result that holds a value adds the outermost link and keeps both the Uncertain
// code and the value: the value is not dropped and the code is not replaced.
// @relation(AC-CL-DIAG-014-UA-ANNOTATE-KEEPS-AN-UNCERTAIN-RESULTS-CODE-AND-VALUE, scope=function)
TEST(ErrorAnnotate, UncertainResultHoldingAValueKeepsTheCodeAndTheValue)
{
  Result<int> uncertain{42, StatusCode{Status::UncertainLastUsableValue}};

  auto annotated =
    annotate(std::move(uncertain), "USER_READ_UNCERTAIN", "the reading is uncertain", "myapp.batch");

  EXPECT_TRUE(annotated.is_uncertain());
  EXPECT_EQ(annotated.status_code().value(), StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(annotated.value_or(-1), 42);
  ErrorChainView view{annotated.status_code()};
  ASSERT_EQ(view.depth(), 1u);
  EXPECT_EQ(view.begin()->code, "USER_READ_UNCERTAIN");
}

// The control for the test above: an UNCERTAIN result holding no value is annotated and still holds none.
// @relation(AC-CL-DIAG-014-UA-ANNOTATE-KEEPS-AN-UNCERTAIN-RESULTS-CODE-AND-VALUE, scope=function)
TEST(ErrorAnnotate, UncertainResultWithoutAValueIsAnnotatedWithoutOne)
{
  Result<int> uncertain{StatusCode{Status::UncertainLastUsableValue}};

  auto annotated =
    annotate(std::move(uncertain), "USER_READ_UNCERTAIN", "the reading is uncertain", "myapp.batch");

  EXPECT_TRUE(annotated.is_uncertain());
  EXPECT_EQ(annotated.status_code().value(), StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(annotated.value_or(-1), -1);
  EXPECT_THROW((void)annotated.value(), UaException);
  EXPECT_EQ(ErrorChainView{annotated.status_code()}.depth(), 1u);
}
