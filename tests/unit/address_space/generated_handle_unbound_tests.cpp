// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <optional>
#include <utility>

#include "ua_file.h"
#include "ua_status.h"

// D5 (Phase 2 SAST hardening): every generated instance-handle accessor guards its optional
// AddressSpace (`mAddressSpace`) before dereferencing it. A default-constructed or moved-from handle
// is UNBOUND (`mAddressSpace` is empty); calling an accessor on it previously dereferenced an empty
// optional (undefined behaviour, and a bugprone-unchecked-optional-access finding once the generated
// tree was gated). The type generator now emits, at the top of every such accessor:
//
//     if (!mAddressSpace)
//     {
//       complete(<Result>{StatusCode{Status::BadInvalidState}});
//       return;
//     }
//
// so an unbound handle reports `Bad_InvalidState` THROUGH the completion (these are `noexcept` async
// methods, so an error is delivered to the callback, never thrown). This mirrors the hand-written
// `if (!mAddressSpace) { ... }` convention used in ConditionInstance/Conditions.
//
// The guard runs SYNCHRONOUSLY (it precedes any strand/executor post), so these tests need no
// executor: the completion has already fired by the time the accessor call returns.
//
// `ua::File` is used as the representative generated handle - it is publicly default-constructible
// and exposes method-, property-, and typed-read accessors, covering the guarded accessor kinds.

namespace
{
using namespace ua;

TEST(GeneratedHandleUnboundGuard, MethodAccessorOnUnboundHandleReportsBadInvalidState)
{
  File unbound;  // default-constructed -> mAddressSpace is empty (unbound)

  std::optional<MethodAccessorResult> result;
  unbound.open_method_async([&result](MethodAccessorResult r) { result.emplace(std::move(r)); });

  ASSERT_TRUE(result.has_value()) << "the unbound guard must invoke the completion synchronously";
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code(), StatusCode{Status::BadInvalidState});
}

TEST(GeneratedHandleUnboundGuard, PropertyAccessorOnUnboundHandleReportsBadInvalidState)
{
  File unbound;

  std::optional<PropertyResult> result;
  unbound.size_property_async([&result](PropertyResult r) { result.emplace(std::move(r)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code(), StatusCode{Status::BadInvalidState});
}

TEST(GeneratedHandleUnboundGuard, TypedReadOnUnboundHandleReportsBadInvalidState)
{
  File unbound;

  std::optional<UInt64Result> result;
  unbound.read_size_async([&result](UInt64Result r) { result.emplace(std::move(r)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code(), StatusCode{Status::BadInvalidState});
}

TEST(GeneratedHandleUnboundGuard, MovedFromHandleIsUnboundAndReportsBadInvalidState)
{
  // Moving a handle empties the source's mAddressSpace, so the moved-from handle is unbound and takes
  // the same guard path. (A default-constructed source is already unbound; the point here is that the
  // guard still fires cleanly on a handle that has been moved out of.)
  File source;
  File sink = std::move(source);

  std::optional<MethodAccessorResult> result;
  // NOLINTNEXTLINE(bugprone-use-after-move) - deliberately exercising the moved-from (unbound) source.
  source.open_method_async([&result](MethodAccessorResult r) { result.emplace(std::move(r)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status_code(), StatusCode{Status::BadInvalidState});
}

}  // namespace
