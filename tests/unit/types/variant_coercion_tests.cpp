// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the Variant typed-coercion primitives Variant::to<T> and Variant::to_vector<T>
// (client design section 7.2 foundation; the tier-2 typed-value sugar builds on these).
//
// Pinned:
//   - to<T> returns a Good Result holding a copy of the contained scalar for each supported type;
//   - to<T> on a wrong type returns Bad_TypeMismatch carrying a source-tagged ErrorDetail whose
//     type.expected / type.actual context names the two BuiltInTypes (exact-type, no numeric coercion);
//   - to<T> on an empty Variant reports actual = Null;
//   - to<T> for an unsupported T returns a clean Bad_NotSupported (compiles, no detail);
//   - to_vector<T> returns the array payload on a match and Bad_TypeMismatch otherwise.
//
// Falsifiability: a primitive that silently coerced Int32->Double would fail the mismatch assertions;
// one that dropped the ErrorDetail would fail the source/context assertions; one that flattened the
// element type wrongly would fail the to_vector payload assertion.

#include "test_utilities.h"

#include "ua_array.h"
#include "ua_error_detail_keys.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using ua::Array;
using ua::BuiltInTypeId;
using ua::ContextKeys;
using ua::Status;
using ua::String;
using ua::Variant;

namespace
{

// --- to<T>: Good coercion for representative scalar types ---

TEST(VariantCoercionTest, ToInt32ReturnsHeldValue)
{
  Variant value{int32_t{42}};
  auto result = value.to<int32_t>();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), 42);
}

TEST(VariantCoercionTest, ToDoubleReturnsHeldValue)
{
  Variant value{double{3.5}};
  auto result = value.to<double>();
  ASSERT_TRUE(result.is_good());
  EXPECT_DOUBLE_EQ(result.value(), 3.5);
}

TEST(VariantCoercionTest, ToBoolReturnsHeldValue)
{
  Variant value{true};
  auto result = value.to<bool>();
  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value());
}

TEST(VariantCoercionTest, ToStringReturnsHeldValue)
{
  Variant value{String{"hello"}};
  auto result = value.to<String>();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), String{"hello"});
}

// --- to<T>: mismatch carries Bad_TypeMismatch + expected/actual BuiltInType, source-tagged ---

TEST(VariantCoercionTest, ToWrongTypeReturnsTypeMismatchWithBothTypeIds)
{
  Variant value{int32_t{7}};
  auto result = value.to<double>();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());

  ASSERT_NE(result.shared_detail(), nullptr)
    << "a type mismatch must carry an ErrorDetail (never a bare bad status)";
  EXPECT_EQ(result.shared_detail()->source, "Variant") << "the coercion error must be source-tagged";
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Double");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Int32");
}

TEST(VariantCoercionTest, ToDoesNotNumericallyCoerce)
{
  // A Variant holding Int32 must NOT coerce to Int64 (exact-type extraction only).
  Variant value{int32_t{5}};
  auto result = value.to<int64_t>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Int64");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Int32");
}

TEST(VariantCoercionTest, ToEmptyVariantReportsActualNull)
{
  Variant value;  // empty
  auto result = value.to<int32_t>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Null");
}

// --- to<T>: unsupported T compiles and returns a clean Bad_NotSupported ---

TEST(VariantCoercionTest, ToUnsupportedTypeReturnsCleanBadNotSupported)
{
  Variant value{int32_t{1}};
  // std::string is not a built-in scalar type of a Variant (ua::String is); the call must still
  // COMPILE and return a clean Bad rather than fail to instantiate.
  auto result = value.to<std::string>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadNotSupported}.value());
  EXPECT_EQ(result.shared_detail(), nullptr) << "an unsupported-T Bad is clean (no mismatch detail)";
}

// --- to_vector<T> ---

TEST(VariantCoercionTest, ToVectorReturnsArrayPayload)
{
  Array<int32_t> array;
  array.push_back(1);
  array.push_back(2);
  array.push_back(3);
  Variant value{array};

  auto result = value.to_vector<int32_t>();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), (std::vector<int32_t>{1, 2, 3}));
}

TEST(VariantCoercionTest, ToVectorWrongElementTypeReturnsTypeMismatch)
{
  Array<int32_t> array;
  array.push_back(9);
  Variant value{array};

  auto result = value.to_vector<double>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Double");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Int32");
}

TEST(VariantCoercionTest, ToVectorOnScalarReturnsTypeMismatch)
{
  Variant value{int32_t{7}};  // scalar, not an array
  auto result = value.to_vector<int32_t>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
}

// --- C1: moved-from-array Variant must not std::terminate in the noexcept coercers ---

TEST(VariantCoercionTest, CoercingMovedFromArrayReportsNullWithoutAborting)
{
  // A moved-from array Variant keeps its ArrayGroup alternative (std::variant preserves the index on
  // move) but the backing wrapper is moved out (operator bool() == false). empty() is therefore false,
  // so the pre-fix `empty() ? Null : get_built_in_type()` error path called the THROWING
  // get_built_in_type() from a noexcept body -> std::terminate. The noexcept-safe actual_type_or_null()
  // must report Null here for BOTH coercers and never abort.
  Array<int32_t> array;
  array.push_back(1);
  array.push_back(2);
  Variant source{array};
  Variant sink{std::move(source)};  // source is now the moved-from-array state (null backing wrapper)

  auto scalar = source.to<int32_t>();
  ASSERT_TRUE(scalar.is_bad());
  EXPECT_EQ(scalar.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(scalar.shared_detail(), nullptr);
  EXPECT_EQ(
    ::ua::test_utils::error_context(scalar.shared_detail().get(), ContextKeys::typeActual.value()), "Null");

  auto vector = source.to_vector<int32_t>();
  ASSERT_TRUE(vector.is_bad());
  EXPECT_EQ(vector.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(vector.shared_detail(), nullptr);
  EXPECT_EQ(
    ::ua::test_utils::error_context(vector.shared_detail().get(), ContextKeys::typeActual.value()), "Null");
}

// --- N1: scalar to<T> on a LIVE array renders the array-ness of the actual type ---

TEST(VariantCoercionTest, ScalarCoercionOnLiveArrayRendersArrayActual)
{
  // A live Array<int32> extracted with the SCALAR to<int32> must not render the nonsensical
  // actual=Int32 (which reads as "expected Int32, got Int32"). The array-ness of the held value is
  // shown so the mismatch is legible.
  Array<int32_t> array;
  array.push_back(7);
  Variant value{array};

  auto result = value.to<int32_t>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Int32");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()),
    "Int32[]");
}

// --- try_as<Array<T>>: the borrowing array accessor ---
//
// The array counterpart of the scalar try_as. Before it existed the only way to read an array
// without throwing was to<Array<T>>/to_vector<T>, both of which COPY - so a caller that only
// wanted to look at the elements had no way to avoid the copy.

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, TryAsArrayBorrowsTheContainedArray)
{
  Array<double> array;
  array.push_back(1.5);
  array.push_back(2.5);
  Variant value{array};

  const Array<double>* borrowed = value.try_as<Array<double>>();
  ASSERT_NE(borrowed, nullptr);
  ASSERT_EQ(borrowed->size(), 2u);
  EXPECT_DOUBLE_EQ(borrowed->payload()[0], 1.5);
  // It BORROWS: the pointer addresses the Variant's own array, not a copy of it.
  EXPECT_EQ(borrowed, value.try_as<Array<double>>());
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, TryAsArrayReturnsNullOnElementTypeMismatch)
{
  Array<double> array;
  array.push_back(1.5);
  Variant value{array};

  EXPECT_EQ(value.try_as<Array<int32_t>>(), nullptr);
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, TryAsArrayReturnsNullOnAScalarOrEmptyVariant)
{
  Variant scalar{2.5};
  EXPECT_EQ(scalar.try_as<Array<double>>(), nullptr);

  Variant empty;
  EXPECT_EQ(empty.try_as<Array<double>>(), nullptr);
}

// --- to<Array<T>>: the copying array accessor ---

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, ToArrayCopiesTheContainedArray)
{
  Array<double> array;
  array.push_back(1.5);
  array.push_back(2.5);
  Variant value{array};

  auto result = value.to<Array<double>>();
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 2u);
  EXPECT_DOUBLE_EQ(result.value().payload()[1], 2.5);
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, ToArrayReportsExpectedWithItsArraySuffix)
{
  // "expected Double, actual Int32[]" would read as a scalar/array confusion that did not happen.
  // The expected side carries its own [] so the two sides are comparable.
  Array<int32_t> array;
  array.push_back(7);
  Variant value{array};

  auto result = value.to<Array<double>>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadTypeMismatch}.value());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Double[]");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()),
    "Int32[]");
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, ToArrayOnAScalarReportsTheScalarActual)
{
  Variant scalar{2.5};

  auto result = scalar.to<Array<double>>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Double[]");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Double");
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, ToArrayOnAnEmptyVariantReportsNullActual)
{
  Variant empty;

  auto result = empty.to<Array<double>>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Null");
}

// @relation(AC-COMP-SDK-POST-VARIANT-ARRAY, scope=function)
TEST(VariantArrayAccessTest, ToVectorStillReportsTheElementTypeWithoutASuffix)
{
  // to_vector<T> asks for a std::vector<T>, so both sides of ITS mismatch are element types. This
  // pins the difference from to<Array<T>> above rather than leaving it to chance.
  Array<int32_t> array;
  array.push_back(7);
  Variant value{array};

  auto result = value.to_vector<double>();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeExpected.value()),
    "Double");
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::typeActual.value()), "Int32");
}

}  // namespace
